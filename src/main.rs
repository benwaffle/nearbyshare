include!(concat!(env!("OUT_DIR"), "/mod.rs"));

use std::{io::{self, Write}, collections::HashMap};

use aes::cipher::{BlockDecryptMut, block_padding::Pkcs7, KeyIvInit, BlockEncryptMut};
use hkdf::Hkdf;
use hmac::Mac;
use mdns_sd::{ServiceDaemon, ServiceInfo};
use base64::{engine::general_purpose, Engine as _};
use p256::{ecdh::EphemeralSecret, EncodedPoint, elliptic_curve::{generic_array::GenericArray, sec1::FromEncodedPoint}, PublicKey};
use protobuf::{Message, SpecialFields, MessageField, Enum};
use rand::{RngCore, rngs::OsRng};
use sha2::{Sha512, Digest, Sha256};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

use crate::{offline_wire_formats::{OfflineFrame, ConnectionResponseFrame, connection_response_frame::ResponseStatus, os_info::OsType, OsInfo, offline_frame, v1frame::FrameType, payload_transfer_frame::{PacketType, payload_header::PayloadType, PayloadHeader, PayloadChunk, payload_chunk::Flags}, PayloadTransferFrame}, ukey::{Ukey2ClientInit, Ukey2ServerInit, Ukey2Message, Ukey2HandshakeCipher, Ukey2Alert, ukey2message, Ukey2ClientFinished}, securemessage::{PublicKeyType, EcP256PublicKey, GenericPublicKey, SecureMessage, HeaderAndBody, SigScheme, Header, EncScheme}, securegcm::GcmMetadata, device_to_device_messages::DeviceToDeviceMessage, wire_format::{Frame, frame, PairedKeyEncryptionFrame, paired_key_result_frame, PairedKeyResultFrame}};

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
    dbg!(msg_len);
    let mut buf = vec![0u8; msg_len];
    let mut read = 0;
    while read < msg_len {
        let n = socket.read(&mut buf[read..]).await.unwrap();
        read += n;
    }
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

fn verify_and_decrypt_d2d(secure_message: SecureMessage, decrypt_key: &[u8], receive_hmac_key: &[u8]) -> Result<DeviceToDeviceMessage, Box<dyn std::error::Error>> {
    let header_and_body = HeaderAndBody::parse_from_bytes(secure_message.header_and_body())?;

    let gcm_metadata = GcmMetadata::parse_from_bytes(header_and_body.header.public_metadata())?;

    if header_and_body.header.encryption_scheme() != EncScheme::AES_256_CBC {
        return Err("unsupported encryption scheme".into());
    }
    if gcm_metadata.type_() != securegcm::Type::DEVICE_TO_DEVICE_MESSAGE {
        return Err(format!("unsupported gcm type: {:?}", gcm_metadata.type_()).into());
    }

    let mut sig = hmac::Hmac::<Sha256>::new_from_slice(&receive_hmac_key).unwrap();
    sig.update(secure_message.header_and_body());
    sig.verify_slice(secure_message.signature())?;

    let decryptor = Aes256CbcDec::new_from_slices(&decrypt_key, header_and_body.header.iv())?;
    let res = decryptor.decrypt_padded_vec_mut::<Pkcs7>(header_and_body.body())?;

    Ok(DeviceToDeviceMessage::parse_from_bytes(&res)?)
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
        frame.v1 = Some(v1frame).into();

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

async fn send_frame(socket: &mut TcpStream, frame: &Frame, encrypt_key: &[u8], send_hmac_key: &[u8], server_seq_num: &mut i32) {
    let data = frame.write_to_bytes().unwrap();

    let id = rand::thread_rng().next_u64() as i64;
    let frames = encode_payload_chunks(id, &data);

    for frame in frames.iter() {
        *server_seq_num += 1;

        let mut d2dmsg = DeviceToDeviceMessage::new();
        d2dmsg.set_sequence_number(*server_seq_num);
        d2dmsg.set_message(frame.write_to_bytes().unwrap());

        let securemessage = sign_and_encrypt_d2d(&encrypt_key, &send_hmac_key, &d2dmsg);
        write_msg(socket, &securemessage).await;
    }
}

#[derive(Debug)]
enum Payload {
    Frame(wire_format::Frame),
    Bytes(Vec<u8>),
}

async fn read_full_payload_transfer(socket: &mut TcpStream, decrypt_key: &[u8], receive_hmac_key: &[u8], client_seq_num: &mut i32) -> Payload {
    let mut payload_bytes: Vec<u8> = vec![];
    let mut id = None;
    let mut payload_type = None;

    loop {
        *client_seq_num += 1;

        let buf = read_msg(socket).await;
        std::fs::File::create(format!("raw{}.buf", *client_seq_num)).unwrap().write_all(&buf).unwrap();
        let secure_message = SecureMessage::parse_from_bytes(&buf).unwrap();

        let d2dmsg = verify_and_decrypt_d2d(secure_message, &decrypt_key, &receive_hmac_key).unwrap();
        std::fs::File::create(format!("d2dmsg{}.buf", *client_seq_num)).unwrap().write_all(d2dmsg.message()).unwrap();
        assert_eq!(d2dmsg.sequence_number(), *client_seq_num);

        let offline_frame = OfflineFrame::parse_from_bytes(d2dmsg.message()).unwrap();
        println!("offline_frame: {:?}", offline_frame);
        assert_eq!(offline_frame.v1.type_(), FrameType::PAYLOAD_TRANSFER);
        assert_eq!(offline_frame.v1.payload_transfer.packet_type(), PacketType::DATA);

        let header = &offline_frame.v1.payload_transfer.payload_header;
        assert_eq!(offline_frame.v1.payload_transfer.payload_chunk.offset() as usize, payload_bytes.len());

        if payload_type == None {
            payload_type = Some(header.type_());
        } else {
            assert_eq!(payload_type, Some(header.type_()));
        }

        if id == None {
            id = Some(header.id());
        } else {
            assert_eq!(id, Some(header.id()));
        }

        let buf = offline_frame.v1.payload_transfer.payload_chunk.body();
        payload_bytes.extend_from_slice(buf);

        if offline_frame.v1.payload_transfer.payload_chunk.flags() & Flags::LAST_CHUNK.value() != 0 {
            break;
        }
    }

    dbg!(payload_bytes.len());
    match payload_type {
        Some(PayloadType::BYTES) => Payload::Frame(Frame::parse_from_bytes(&payload_bytes).unwrap()),
        Some(PayloadType::FILE) => Payload::Bytes(payload_bytes),
        _ => panic!("unknown payload type {:?}", payload_type),
    }
}

#[derive(Debug)]
struct TransferState {
    data: Vec<u8>,
    typ: PayloadType,
}

#[derive(Debug)]
enum TransferResult {
    Nothing,
    Frame(wire_format::Frame),
    Bytes(i64, Vec<u8>),
    Keepalive,
}

async fn read_next_transfer(transfers: &mut HashMap<i64, TransferState>, socket: &mut TcpStream, decrypt_key: &[u8], receive_hmac_key: &[u8], client_seq_num: &mut i32) -> TransferResult {
    dbg!("---------------------------------------------\n\n");
    *client_seq_num += 1;

    let buf = read_msg(socket).await;
    //std::fs::File::create(format!("raw{}.buf", *client_seq_num)).unwrap().write_all(&buf).unwrap();
    let secure_message = SecureMessage::parse_from_bytes(&buf).unwrap();

    let d2dmsg = verify_and_decrypt_d2d(secure_message, &decrypt_key, &receive_hmac_key).unwrap();
    //std::fs::File::create(format!("d2dmsg{}.buf", *client_seq_num)).unwrap().write_all(d2dmsg.message()).unwrap();
    assert_eq!(d2dmsg.sequence_number(), *client_seq_num);

    let offline_frame = OfflineFrame::parse_from_bytes(d2dmsg.message()).unwrap();
    println!("offline_frame: {:?}", offline_frame);
    assert_eq!(offline_frame.v1.type_(), FrameType::PAYLOAD_TRANSFER);
    assert_eq!(offline_frame.v1.payload_transfer.packet_type(), PacketType::DATA);

    let header = &offline_frame.v1.payload_transfer.payload_header;

    let transfer = transfers.entry(header.id()).or_insert_with(|| TransferState {
        data: vec![],
        typ: header.type_()
    });
    assert_eq!(offline_frame.v1.payload_transfer.payload_chunk.offset() as usize, transfer.data.len());
    assert_eq!(transfer.typ, header.type_());

    let buf = offline_frame.v1.payload_transfer.payload_chunk.body();
    transfer.data.extend_from_slice(buf);

    if offline_frame.v1.payload_transfer.payload_chunk.flags() & Flags::LAST_CHUNK.value() != 0 {
        let transfer = transfers.remove(&header.id()).unwrap();
        let res = match transfer.typ {
            PayloadType::BYTES => TransferResult::Frame(Frame::parse_from_bytes(&transfer.data).unwrap()),
            PayloadType::FILE  => TransferResult::Bytes(header.id(), transfer.data),
            _ => panic!("unknown payload type {:?}", transfer.typ),
        };
        //println!("transfer complete: {:?}", res);
        return res
    }

    TransferResult::Nothing
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
        // TODO: handle lengths shorter than 32 bytes
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

    let mut server_seq_num = 0i32;
    let mut client_seq_num = 0i32;

    // paired key encryption
    let Payload::Frame(frame) = read_full_payload_transfer(&mut socket, &decrypt_key, &receive_hmac_key, &mut client_seq_num).await else {
        panic!("expected frame")
    };
    println!("< {:?}", frame);

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

    send_frame(&mut socket, &frame, &encrypt_key, &send_hmac_key, &mut server_seq_num).await;

    let Payload::Frame(frame) = read_full_payload_transfer(&mut socket, &decrypt_key, &receive_hmac_key, &mut client_seq_num).await else {
        panic!("expected frame")
    };
    println!("< {:?}", frame);

    // paired key result
    let mut paired_key_result = PairedKeyResultFrame::new();
    paired_key_result.set_status(paired_key_result_frame::Status::UNABLE);

    let mut v1frame = wire_format::V1Frame::new();
    v1frame.set_type(wire_format::v1frame::FrameType::PAIRED_KEY_RESULT);
    v1frame.paired_key_result = Some(paired_key_result).into();

    let mut frame = wire_format::Frame::new();
    frame.set_version(frame::Version::V1);
    frame.v1 = Some(v1frame).into();

    send_frame(&mut socket, &frame, &encrypt_key, &send_hmac_key, &mut server_seq_num).await;

    let Payload::Frame(frame) = read_full_payload_transfer(&mut socket, &decrypt_key, &receive_hmac_key, &mut client_seq_num).await else {
        panic!("expected frame")
    };
    println!("< {:?}", frame);
    assert_eq!(frame.v1.type_(), wire_format::v1frame::FrameType::INTRODUCTION);
    let files = &frame.v1.introduction.file_metadata;
    for file in files {
        let filename = file.name();
        let typ = file.type_();
        let size = file.size();
        let mime_type = file.mime_type();

        println!("file: {} {:?} {} {}", filename, typ, size, mime_type);
    }
    // TODO: handle text transfers

    println!("Pin code: {}", generate_pin_code(&authentication_string));
    print!("Accept (y/n)? ");
    io::stdout().flush().unwrap();
    let line = io::stdin().lines().next().unwrap().unwrap();

    let mut response = wire_format::ConnectionResponseFrame::new();
    if line == "y" {
        println!("Accepting...");
        response.set_status(wire_format::connection_response_frame::Status::ACCEPT);
    } else {
        println!("Rejecting...");
        response.set_status(wire_format::connection_response_frame::Status::REJECT);
    }

    let mut v1frame = wire_format::V1Frame::new();
    v1frame.set_type(wire_format::v1frame::FrameType::RESPONSE);
    v1frame.connection_response = Some(response).into();

    let mut frame = wire_format::Frame::new();
    frame.set_version(frame::Version::V1);
    frame.v1 = Some(v1frame).into();

    send_frame(&mut socket, &frame, &encrypt_key, &send_hmac_key, &mut server_seq_num).await;

    let mut transfers = HashMap::new();
    loop {
        match read_next_transfer(
            &mut transfers,
            &mut socket,
            &decrypt_key,
            &receive_hmac_key,
            &mut client_seq_num,
        ).await {
            TransferResult::Nothing => {},
            TransferResult::Keepalive => panic!("keepalive"),
            TransferResult::Frame(frame) => {
                dbg!(frame);
            },
            TransferResult::Bytes(id, data) => {
                dbg!(id, files);
                if data.len() > 100 {
                    dbg!(&data[..100]);
                } else {
                    dbg!(&data);
                }

                let file = files.iter().find(|f| f.payload_id() == id).unwrap();
                println!("received file: {} {:?}", file.name(), file.type_());
                std::fs::File::create(file.name()).unwrap().write_all(&data).unwrap();
            },
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
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
