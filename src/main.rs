include!(concat!(env!("OUT_DIR"), "/mod.rs"));

use aes::cipher::{KeyIvInit, BlockDecryptMut, block_padding::Pkcs7};
use hkdf::Hkdf;
use mdns_sd::{ServiceDaemon, ServiceInfo};
use base64::{engine::general_purpose, Engine as _};
use p256::{ecdh::EphemeralSecret, EncodedPoint, elliptic_curve::{generic_array::GenericArray, sec1::FromEncodedPoint}, PublicKey};
use protobuf::{Message, SpecialFields, MessageField};
use rand::{RngCore, rngs::OsRng};
use sha2::{Sha512, Digest, Sha256};
use tokio::{io::{Result, AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};
use hmac::{Mac};

use crate::{offline_wire_formats::{OfflineFrame, ConnectionResponseFrame, connection_response_frame::ResponseStatus, os_info::OsType, OsInfo, offline_frame, V1Frame, v1frame::FrameType, payload_transfer_frame::{PacketType, payload_header::PayloadType}}, ukey::{Ukey2ClientInit, Ukey2ServerInit, Ukey2Message, Ukey2HandshakeCipher, Ukey2Alert, ukey2message, Ukey2ClientFinished}, securemessage::{PublicKeyType, EcP256PublicKey, GenericPublicKey, SecureMessage, HeaderAndBody, SigScheme}, securegcm::GcmMetadata, device_to_device_messages::DeviceToDeviceMessage, wire_format::Frame};

fn b64(bytes: &[u8]) -> String {
    let str = general_purpose::STANDARD.encode(bytes);
    return str.replace("=", "")
              .replace("/", "_")
              .replace("+", "-");
}

fn broadcast_mdns(port: u16) {
    let service_type = "_FC9F5ED42C8A._tcp.local.";

    let mut name_bytes = [0x23, 0, 0, 0, 0, 0xfc, 0x9f, 0x5e, 0, 0];
    rand::thread_rng().fill_bytes(&mut name_bytes[1..4]);

    let instance_name = b64(&name_bytes);
    println!("dns-sd name: {}", instance_name);

    // Create a daemon
    let mdns = ServiceDaemon::new().expect("Failed to create daemon");

    // Create a service info.
    let host_ipv4 = "192.168.1.165";
    let host_name = "192.168.1.165.local.";

    let flags: u8 = 0b00000110;
    let n = [flags, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x3, b'b', b'e', b'n'];

    let properties = [("n", b64(&n))];

    let my_service = ServiceInfo::new(
        service_type,
        &instance_name,
        host_name,
        host_ipv4,
        port,
        &properties[..],
    ).unwrap();

    // Register with the daemon, which publishes the service.
    mdns.register(my_service).expect("Failed to register our service");
}

async fn start_server(listener: TcpListener) {
    loop {
        let (socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            process(socket).await;
        });
    }
}

async fn read_msg_len(socket: &mut TcpStream) -> usize {
    let mut msg_len = [0u8; 4];
    let n = socket.read(&mut msg_len).await.unwrap();
    assert_eq!(n, 4);

    u32::from_be_bytes(msg_len) as usize
}

async fn read_msg(socket: &mut TcpStream) -> Vec<u8> {
    let msg_len = read_msg_len(socket).await;
    let mut buf = vec![0u8; msg_len];
    socket.read(&mut buf).await.unwrap();
    buf
}

fn do_hkdf(salt: &[u8], input_key: &[u8], info: &[u8], size: usize) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), input_key);
    let mut okm = vec![0u8; size];
    hkdf.expand(info, &mut okm).unwrap();
    okm
}

impl From<PublicKey> for securemessage::GenericPublicKey {
    fn from(public_key: PublicKey) -> Self {
        let encoded = EncodedPoint::from(public_key);

        let mut public_key_pb = GenericPublicKey::new();
        public_key_pb.set_type(PublicKeyType::EC_P256.into());

        let x = encoded.x().unwrap().to_vec();
        let y = encoded.y().unwrap().to_vec();

        // securemessage.proto requires two's complement. p256 gives unsigned encodings, so just prepend a 0.
        let x = [vec![0u8], x].concat();
        let y = [vec![0u8], y].concat();

        public_key_pb.ec_p256_public_key = Some(EcP256PublicKey {
            x: Some(x),
            y: Some(y),
            special_fields: SpecialFields::default(),
        }).into();

        public_key_pb
    }
}

impl From<securemessage::GenericPublicKey> for PublicKey {
    fn from(gpk: securemessage::GenericPublicKey) -> Self {
        assert_eq!(gpk.type_(), PublicKeyType::EC_P256);

        let x = gpk.ec_p256_public_key.x.as_ref().unwrap();
        let y = gpk.ec_p256_public_key.y.as_ref().unwrap();
        // cut off leading 0x00 byte from incoming two's complement ints, as p256 uses unsigned ints
        let x = &x[x.len()-32..];
        let y = &y[y.len()-32..];

        // positive integers in two's complement are represented the same way as unsigned integers
        let client_pub_key_pt = EncodedPoint::from_affine_coordinates(
            GenericArray::<u8, p256::U32>::from_slice(x),
            GenericArray::<u8, p256::U32>::from_slice(y),
            false,
        );
        PublicKey::from_encoded_point(&client_pub_key_pt).unwrap()
    }
}

async fn write_msg(socket: &mut TcpStream, message: &impl protobuf::Message) {
    let bytes = message.write_to_bytes().unwrap();
    socket.write_all(&(bytes.len() as u32).to_be_bytes()).await.unwrap();
    socket.write_all(&bytes).await.unwrap();
}

async fn process(mut socket: TcpStream) -> ! {
    loop {
        // ConnectionRequestFrame
        let buf = read_msg(&mut socket).await;

        let offline = OfflineFrame::parse_from_bytes(&buf).unwrap();
        println!("< {:?}", offline.v1.type_.unwrap());
        let endpoint_info = offline.v1.connection_request.endpoint_info.as_ref().unwrap();
        println!("endpoint_info: {:?}", endpoint_info);

        let device_type_id = (endpoint_info[0] & 0b1110) >> 1;
        let device_type = match device_type_id {
            0 => "unknown",
            1 => "phone",
            2 => "tablet",
            3 => "laptop",
            _ => "unknown2",
        };
        println!("device_type: {}", device_type);

        let device_name_size = endpoint_info[17] as usize;
        let device_name = std::str::from_utf8(&endpoint_info[18..18+device_name_size]).unwrap();
        println!("device_name: {}", device_name);

        // UKEY2 Client Init
        let buf = read_msg(&mut socket).await;

        let m1 = buf.clone();

        let ukey2_message = Ukey2Message::parse_from_bytes(&buf).unwrap();
        println!("< {:?}", ukey2_message);

        let ukey2_client_init = Ukey2ClientInit::parse_from_bytes(ukey2_message.message_data()).unwrap();
        println!("< {:?}", ukey2_client_init);

        assert!(ukey2_client_init.next_protocol.unwrap() == "AES_256_CBC-HMAC_SHA256");

        let cipher = ukey2_client_init.cipher_commitments.iter().find(|c| c.handshake_cipher() == Ukey2HandshakeCipher::P256_SHA512).unwrap();

        let secret_key = EphemeralSecret::random(&mut OsRng);
        let public_key_pb = GenericPublicKey::from(secret_key.public_key());

        let mut random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random);

        let server_init = Ukey2ServerInit {
            version: Some(1),
            random: Some(random.into()),
            handshake_cipher: Some(Ukey2HandshakeCipher::P256_SHA512.into()),
            public_key: Some(public_key_pb.write_to_bytes().unwrap()),
            special_fields: SpecialFields::default(),
        };
        let server_init = Ukey2Message {
            message_type: Some(ukey2message::Type::SERVER_INIT.into()),
            message_data: Some(server_init.write_to_bytes().unwrap()),
            special_fields: SpecialFields::default(),
        };

        println!("> {:?}", server_init);
        write_msg(&mut socket, &server_init).await;
        let m2 = server_init.write_to_bytes().unwrap();

        // UKEY2 Client Finished
        let buf = read_msg(&mut socket).await;

        println!("uk2 alert: {:?}", Ukey2Alert::parse_from_bytes(&buf));

        let ukey2_message = Ukey2Message::parse_from_bytes(&buf).unwrap();
        println!("< {:?}", ukey2_message);
        assert_eq!(ukey2_message.message_type, Some(ukey2message::Type::CLIENT_FINISH.into()));

        // verify commitment hash
        assert_eq!(Sha512::digest(buf).as_slice(), cipher.commitment());

        let ukey2_client_finished = Ukey2ClientFinished::parse_from_bytes(ukey2_message.message_data()).unwrap();

        let client_pub_key = GenericPublicKey::parse_from_bytes(&ukey2_client_finished.public_key.unwrap()).unwrap();
        let client_pub_key = PublicKey::from(client_pub_key);

        let shared_secret = Sha256::digest(secret_key.diffie_hellman(&client_pub_key).raw_secret_bytes());

        // deriving keys
        let m3 = [m1, m2].concat();

        let authentication_string = do_hkdf(b"UKEY2 v1 auth", &shared_secret, &m3, 32);
        let next_protocol_secret = do_hkdf(b"UKEY2 v1 next", &shared_secret, &m3, 32);

        // this is sha256("D2D")
        let d2d_salt = hex::decode("82AA55A0D397F88346CA1CEE8D3909B95F13FA7DEB1D4AB38376B8256DA85510").unwrap();
        let d2d_client_key = do_hkdf(&d2d_salt, &next_protocol_secret, b"client", 32);
        let d2d_server_key = do_hkdf(&d2d_salt, &next_protocol_secret, b"server", 32);

        // this is sha256("SecureMessage")
        let salt = hex::decode("BF9D2A53C63616D75DB0A7165B91C1EF73E537F2427405FA23610A4BE657642E").unwrap();
        let decrypt_key = do_hkdf(&salt, &d2d_client_key, b"ENC:2", 32);
        let receive_hmac_key = do_hkdf(&salt, &d2d_client_key, b"SIG:1", 32);
        let _encrypt_key = do_hkdf(&salt, &d2d_server_key, b"ENC:2", 32);
        let _send_hmac_key = do_hkdf(&salt, &d2d_server_key, b"SIG:1", 32);

        fn generate_pin_code(auth_string: &[u8]) -> String {
            let mut hash: i32 = 0;
            let mut multiplier: i32 = 1;
            for byte in auth_string {
                hash = (hash + (*byte as i8 as i32) * multiplier) % 9973;
                multiplier = (multiplier * 31) % 9973;
            }
            return format!("{:04}", hash.abs());
        }

        dbg!(generate_pin_code(&authentication_string));

        // Connection Response
        let mut connection_response = ConnectionResponseFrame::new();
        connection_response.set_status(0);
        connection_response.set_response(ResponseStatus::ACCEPT);
        connection_response.os_info = MessageField::some(OsInfo { type_: Some(OsType::LINUX.into()), special_fields: SpecialFields::default() });

        let mut v1frame = V1Frame::new();
        v1frame.set_type(FrameType::CONNECTION_RESPONSE.into());
        v1frame.connection_response = MessageField::some(connection_response);

        let connection_response = OfflineFrame {
            version: Some(offline_frame::Version::V1.into()),
            v1: MessageField::some(v1frame),
            special_fields: SpecialFields::default(),
        };
        write_msg(&mut socket, &connection_response).await;

        // key exchange complete

        // connection response from android?
        let buf = read_msg(&mut socket).await;
        let offline_frame = OfflineFrame::parse_from_bytes(&buf).unwrap();
        println!("< {:?}", offline_frame);

        // paired key encryption
        let buf = read_msg(&mut socket).await;
        std::fs::write("enc.buf", &buf).unwrap();

        let secure_message = SecureMessage::parse_from_bytes(&buf).unwrap();
        let header_and_body = HeaderAndBody::parse_from_bytes(secure_message.header_and_body()).unwrap();
        let gcm_metadata = GcmMetadata::parse_from_bytes(header_and_body.header.public_metadata()).unwrap();
        assert_eq!(header_and_body.header.signature_scheme(), SigScheme::HMAC_SHA256);
        assert_eq!(gcm_metadata.type_(), securegcm::Type::DEVICE_TO_DEVICE_MESSAGE);

        let mut sig = hmac::Hmac::<Sha256>::new_from_slice(&receive_hmac_key).unwrap();
        sig.update(secure_message.header_and_body());
        sig.verify_slice(secure_message.signature()).unwrap();

        let decryptor = cbc::Decryptor::<aes::Aes256>::new(decrypt_key.as_slice().into(), header_and_body.header.iv().into());
        let mut buf = vec![0u8; header_and_body.body().len()];
        let res = decryptor.decrypt_padded_b2b_mut::<Pkcs7>(header_and_body.body(), &mut buf).unwrap();

        let d2dmsg = DeviceToDeviceMessage::parse_from_bytes(&res).unwrap();
        let offline_frame = OfflineFrame::parse_from_bytes(d2dmsg.message()).unwrap();
        dbg!(&offline_frame);

        assert_eq!(offline_frame.v1.type_(), FrameType::PAYLOAD_TRANSFER);
        assert_eq!(offline_frame.v1.payload_transfer.packet_type(), PacketType::DATA);
        assert_eq!(offline_frame.v1.payload_transfer.payload_header.type_(), PayloadType::BYTES); // bytes means protobuf message

        let buf = offline_frame.v1.payload_transfer.payload_chunk.body();
        let frame = Frame::parse_from_bytes(buf).unwrap();
        dbg!(frame);

        std::thread::sleep(std::time::Duration::from_secs(3));

        todo!();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    println!("Listening on {}", listener.local_addr().unwrap());
    broadcast_mdns(listener.local_addr().unwrap().port());

    start_server(listener).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slice() {
        let asdf = "abcdef";
        let x = &asdf[asdf.len()-2..];
        assert_eq!(x, "ef");
    }
}
