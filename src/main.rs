include!(concat!(env!("OUT_DIR"), "/mod.rs"));

use mdns_sd::{ServiceDaemon, ServiceInfo};
use base64::{engine::general_purpose, Engine as _};
use protobuf::Message;
use rand::RngCore;
use tokio::{io::{Result, AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

use crate::offline_wire_formats::{OfflineFrame, v1frame::FrameType};

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

async fn process(mut socket: TcpStream) {
    loop {
        let mut msg_len = [0u8; 4];
        let n = socket.read(&mut msg_len).await.unwrap();
        assert!(n == 4);

        let msg_len = u32::from_be_bytes(msg_len);
        println!("message length is {}", msg_len);

        let mut buf = vec![0u8; msg_len as usize];
        let n = socket.read(&mut buf).await.unwrap();
        if n == 0 {
            return;
        }

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

        socket.write_all(&buf[0..n]).await.unwrap();
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
