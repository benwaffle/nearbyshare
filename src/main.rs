include!(concat!(env!("OUT_DIR"), "/mod.rs"));

use aes::cipher::{BlockDecryptMut, block_padding::Pkcs7, KeyIvInit, BlockEncryptMut};
use hkdf::Hkdf;
use hmac::Mac;
use mdns_sd::{ServiceDaemon, ServiceInfo};
use base64::{engine::general_purpose, Engine as _};
use p256::{ecdh::EphemeralSecret, EncodedPoint, elliptic_curve::{generic_array::GenericArray, sec1::FromEncodedPoint}, PublicKey};
use protobuf::{Message, SpecialFields, MessageField, Enum};
use rand::{RngCore, rngs::OsRng};
use sha2::{Sha512, Digest, Sha256};
use tokio::{io::{Result, AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

use crate::{offline_wire_formats::{OfflineFrame, ConnectionResponseFrame, connection_response_frame::ResponseStatus, os_info::OsType, OsInfo, offline_frame, v1frame::FrameType, payload_transfer_frame::{PacketType, payload_header::PayloadType, PayloadHeader, PayloadChunk, payload_chunk::Flags}, PayloadTransferFrame}, ukey::{Ukey2ClientInit, Ukey2ServerInit, Ukey2Message, Ukey2HandshakeCipher, Ukey2Alert, ukey2message, Ukey2ClientFinished}, securemessage::{PublicKeyType, EcP256PublicKey, GenericPublicKey, SecureMessage, HeaderAndBody, SigScheme, Header, EncScheme}, securegcm::GcmMetadata, device_to_device_messages::DeviceToDeviceMessage, wire_format::{Frame, frame, PairedKeyEncryptionFrame}};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

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

fn sign_and_encrypt_d2d(encrypt_key: &[u8], send_hmac_key: &[u8], d2dmsg: &DeviceToDeviceMessage) -> SecureMessage {
    let mut iv = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let encryptor = Aes256CbcEnc::new_from_slices(&encrypt_key, &iv).unwrap();
    let encrypted = encryptor.encrypt_padded_vec_mut::<Pkcs7>(&d2dmsg.write_to_bytes().unwrap());

    let mut gcm_metadata = GcmMetadata::new();
    gcm_metadata.set_type(securegcm::Type::DEVICE_TO_DEVICE_MESSAGE);
    gcm_metadata.set_version(1);

    let mut header = Header::new();
    header.set_signature_scheme(SigScheme::HMAC_SHA256);
    header.set_encryption_scheme(EncScheme::AES_256_CBC);
    header.set_iv(iv);
    header.set_public_metadata(gcm_metadata.write_to_bytes().unwrap());

    let mut header_and_body = HeaderAndBody::new();
    header_and_body.header = Some(header).into();
    header_and_body.body = Some(encrypted);

    let header_and_body_bytes = header_and_body.write_to_bytes().unwrap();
    let mut hmac = hmac::Hmac::<Sha256>::new_from_slice(&send_hmac_key).unwrap();
    hmac.update(&header_and_body_bytes);

    let mut securemessage = SecureMessage::new();
    securemessage.header_and_body = Some(header_and_body.write_to_bytes().unwrap()).into();
    securemessage.signature = Some(hmac.finalize().into_bytes().to_vec()).into();

    securemessage
}

fn encode_payload_chunks(id: i64, data: &[u8]) -> Vec<OfflineFrame> {
    const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024; // TODO: pick a good value
    let mut res = vec![];

    fn new_frame(id: i64, offset: usize, chunk: &[u8], total_size: usize, last: bool) -> OfflineFrame {
        let mut payload_header = PayloadHeader::new();
        payload_header.set_id(id);
        payload_header.set_type(PayloadType::BYTES);
        payload_header.set_total_size(total_size as i64);

        let mut payload_chunk = PayloadChunk::new();
        payload_chunk.set_offset(offset as i64);
        payload_chunk.set_flags(if last { Flags::LAST_CHUNK.value() } else { 0 });
        payload_chunk.body = Some(chunk.to_vec()).into();

        let mut payload_transfer_frame = PayloadTransferFrame::new();
        payload_transfer_frame.set_packet_type(PacketType::DATA);
        payload_transfer_frame.payload_header = Some(payload_header).into();
        payload_transfer_frame.payload_chunk = Some(payload_chunk).into();

        let mut v1frame = offline_wire_formats::V1Frame::new();
        v1frame.set_type(offline_wire_formats::v1frame::FrameType::PAYLOAD_TRANSFER);
        v1frame.payload_transfer = Some(payload_transfer_frame).into();

        let mut frame = OfflineFrame::new();
        frame.set_version(offline_frame::Version::V1);
        frame.v1 = Some(offline_wire_formats::V1Frame::new()).into();

        frame
    }

    for (i, chunk) in data.chunks(MAX_CHUNK_SIZE).enumerate() {
        let offset = i * MAX_CHUNK_SIZE;
        let total_size = data.len();
        res.push(new_frame(id, offset, chunk, total_size, false));
    }

    // last empty chunk with LAST_CHUNK flag set
    res.push(new_frame(id, data.len(), &[], data.len(), true));

    res
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
    let encrypt_key = do_hkdf(&salt, &d2d_server_key, b"ENC:2", 32);
    let send_hmac_key = do_hkdf(&salt, &d2d_server_key, b"SIG:1", 32);

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

    let mut v1frame = offline_wire_formats::V1Frame::new();
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

    let decryptor = Aes256CbcDec::new_from_slices(&decrypt_key, header_and_body.header.iv()).unwrap();
    let res = decryptor.decrypt_padded_vec_mut::<Pkcs7>(header_and_body.body()).unwrap();

    let d2dmsg = DeviceToDeviceMessage::parse_from_bytes(&res).unwrap();
    let offline_frame = OfflineFrame::parse_from_bytes(d2dmsg.message()).unwrap();
    dbg!(&offline_frame);

    assert_eq!(offline_frame.v1.type_(), FrameType::PAYLOAD_TRANSFER);
    assert_eq!(offline_frame.v1.payload_transfer.packet_type(), PacketType::DATA);
    assert_eq!(offline_frame.v1.payload_transfer.payload_header.type_(), PayloadType::BYTES); // bytes means protobuf message

    let buf = offline_frame.v1.payload_transfer.payload_chunk.body();
    let frame = Frame::parse_from_bytes(buf).unwrap();
    dbg!(frame);

    // TODO: read multiple chunks

    // send paired key encryption
    let mut signed_data = vec![0u8; 72];
    rand::thread_rng().fill_bytes(&mut signed_data);

    let mut secret_id_hash = vec![0u8; 6];
    rand::thread_rng().fill_bytes(&mut secret_id_hash);

    let mut paired_key_encryption = PairedKeyEncryptionFrame::new();
    paired_key_encryption.signed_data = Some(signed_data);
    paired_key_encryption.secret_id_hash = Some(secret_id_hash);

    let mut v1frame = wire_format::V1Frame::new();
    v1frame.set_type(wire_format::v1frame::FrameType::PAIRED_KEY_ENCRYPTION);
    v1frame.paired_key_encryption = Some(paired_key_encryption).into();

    let mut frame = wire_format::Frame::new();
    frame.set_version(frame::Version::V1);
    frame.v1 = Some(v1frame).into();

    // payload layer
    let data = frame.write_to_bytes().unwrap();

    let id = 12345;
    let frames = encode_payload_chunks(id, &data);

    for (i, frame) in frames.iter().enumerate() {
        // encryption layer
        let mut d2dmsg = DeviceToDeviceMessage::new();
        d2dmsg.set_sequence_number((i + 1) as i32);
        d2dmsg.set_message(frame.write_to_bytes().unwrap());

        let securemessage = sign_and_encrypt_d2d(&encrypt_key, &send_hmac_key, &d2dmsg);
        write_msg(&mut socket, &securemessage).await;
    }

    std::thread::sleep(std::time::Duration::from_secs(3));

    todo!();
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
