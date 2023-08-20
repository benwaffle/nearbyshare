include!(concat!(env!("OUT_DIR"), "/mod.rs"));

use mdns_sd::{ServiceDaemon, ServiceInfo};
use base64::{engine::general_purpose, Engine as _};
use p256::{ecdh::EphemeralSecret, EncodedPoint, elliptic_curve::{generic_array::GenericArray, sec1::FromEncodedPoint}, PublicKey};
use protobuf::{Message, SpecialFields};
use rand::{RngCore, rngs::OsRng};
use sha2::{Sha512, Digest};
use tokio::{io::{Result, AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

use crate::{offline_wire_formats::OfflineFrame, ukey::{Ukey2ClientInit, Ukey2ServerInit, Ukey2Message, Ukey2HandshakeCipher, Ukey2Alert, ukey2message, Ukey2ClientFinished}, securemessage::{PublicKeyType, EcP256PublicKey, GenericPublicKey}};

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

    let msg_len = u32::from_be_bytes(msg_len);
    return msg_len as usize;
}

async fn process(mut socket: TcpStream) -> ! {
    loop {
        // ConnectionRequestFrame
        let msg_len = read_msg_len(&mut socket).await;
        let mut buf = vec![0u8; msg_len];
        socket.read(&mut buf).await.unwrap();

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
            _ => "really unknown",
        };
        println!("device_type: {}", device_type);

        let device_name_size = endpoint_info[17] as usize;
        let device_name = std::str::from_utf8(&endpoint_info[18..18+device_name_size]).unwrap();
        println!("device_name: {}", device_name);

        // UKEY2 Client Init
        let msg_len = read_msg_len(&mut socket).await;
        let mut buf = vec![0u8; msg_len];
        socket.read(&mut buf).await.unwrap();

        let ukey2_message = Ukey2Message::parse_from_bytes(&buf).unwrap();
        println!("uk2 msg: {:?}", ukey2_message);

        let ukey2_client_init = Ukey2ClientInit::parse_from_bytes(ukey2_message.message_data()).unwrap();
        println!("ukey2_client_init: {:?}", ukey2_client_init);

        let cipher = ukey2_client_init.cipher_commitments.iter().find(|c| c.handshake_cipher() == Ukey2HandshakeCipher::P256_SHA512).unwrap();

        let secret_key = EphemeralSecret::random(&mut OsRng);
        let encoded = EncodedPoint::from(secret_key.public_key());

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

        let bytes = server_init.write_to_bytes().unwrap();
        socket.write_all(&(bytes.len() as u32).to_be_bytes()).await.unwrap();
        socket.write_all(&bytes).await.unwrap();

        // UKEY2 Client Finished
        let msg_len = read_msg_len(&mut socket).await;
        let mut buf = vec![0u8; msg_len];
        socket.read(&mut buf).await.unwrap();

        println!("uk2 alert: {:?}", Ukey2Alert::parse_from_bytes(&buf));

        let ukey2_message = Ukey2Message::parse_from_bytes(&buf).unwrap();
        println!("uk2 msg: {:?}", ukey2_message);
        assert_eq!(ukey2_message.message_type, Some(ukey2message::Type::CLIENT_FINISH.into()));

        // verify commitment hash
        let mut hasher = Sha512::new();
        hasher.update(buf);
        let commitment_hash = hasher.finalize();
        assert_eq!(commitment_hash.as_slice(), cipher.commitment());

        let ukey2_client_finished = Ukey2ClientFinished::parse_from_bytes(ukey2_message.message_data()).unwrap();

        let client_pub_key = GenericPublicKey::parse_from_bytes(&ukey2_client_finished.public_key.unwrap()).unwrap();
        assert_eq!(client_pub_key.type_, Some(PublicKeyType::EC_P256.into()));

        // positive integers in two's complement are represented the same way as unsigned integers
        let client_pub_key_pt = EncodedPoint::from_affine_coordinates(
            GenericArray::from_slice(client_pub_key.ec_p256_public_key.x.as_ref().unwrap().as_slice()),
            GenericArray::from_slice(client_pub_key.ec_p256_public_key.y.as_ref().unwrap().as_slice()),
            false,
        );
        let client_pub_key_pt = PublicKey::from_encoded_point(&client_pub_key_pt).unwrap();

        let shared_secret = secret_key.diffie_hellman(&client_pub_key_pt);

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
