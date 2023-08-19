use mdns_sd::{ServiceDaemon, ServiceInfo};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use tokio::{io::{Result, AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

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
        process(socket).await;
    }
}

async fn process(socket: TcpStream) {
    let mut socket = socket;
    let mut buf = [0; 1024];
    loop {
        let n = socket.read(&mut buf).await.unwrap();
        if n == 0 {
            return;
        }
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
