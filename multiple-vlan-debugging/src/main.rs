use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use gateway_sp_comms::gateway_messages;
use gateway_sp_comms::gateway_messages::version;
use gateway_sp_comms::gateway_messages::Header;
use gateway_sp_comms::gateway_messages::Message;
use gateway_sp_comms::gateway_messages::MessageKind;
use gateway_sp_comms::gateway_messages::MgsRequest;
use nix::sys::socket::setsockopt;
use nix::sys::socket::sockopt;
use std::net::SocketAddrV6;
use std::os::unix::prelude::AsRawFd;
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, default_value_t = gateway_sp_comms::default_discovery_addr())]
    discovery_addr: SocketAddrV6,

    #[clap(short, long)]
    listen_interface: String,

    #[clap(short = 'p', long, default_value_t = 0)]
    listen_port: u16,

    #[clap(required(true))]
    interfaces: Vec<String>,
}

fn addr_for_interface(interface: &str) -> Result<SocketAddrV6> {
    let ifaddrs = nix::ifaddrs::getifaddrs().context("getifaddrs() failed")?;

    for i in ifaddrs {
        if i.interface_name == interface {
            if let Some(addr) =
                i.address.and_then(|s| s.as_sockaddr_in6().copied())
            {
                return Ok(SocketAddrV6::new(
                    addr.ip(),
                    addr.port(),
                    addr.flowinfo(),
                    addr.scope_id(),
                ));
            }
        }
    }

    Err(anyhow!("no address found for interface {interface:?}"))
}

async fn try_discover(socket: &UdpSocket, addr: SocketAddrV6) -> Result<()> {
    let mut buf = [0; gateway_messages::MAX_SERIALIZED_SIZE];
    let request = Message {
        header: Header { version: version::V2, message_id: 1 },
        kind: MessageKind::MgsRequest(MgsRequest::Discover),
    };

    let n = gateway_messages::serialize(&mut buf, &request).unwrap();
    let out = &buf[..n];

    let sent = socket.send_to(out, addr).await.context("send_to() failed")?;
    assert_eq!(n, sent);

    let result = tokio::time::timeout(
        Duration::from_secs(3),
        socket.recv_from(&mut buf),
    )
    .await
    .context("timed out waiting for reply")?;

    let (recvd, src_addr) = match result {
        Ok((n, src_addr)) => (&buf[..n], src_addr),
        Err(err) => bail!("error receiving: {err}"),
    };

    let (message, _) = gateway_messages::deserialize::<Message>(recvd)
        .with_context(|| format!("failed to deserialize response {recvd:?}"))?;

    println!("got response from {src_addr}: {message:?}");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let ifaddrs = nix::ifaddrs::getifaddrs().context("getifaddrs() failed")?;
    for i in ifaddrs {
        if let Some(addr) = i.address.and_then(|s| s.as_sockaddr_in6().copied())
        {
            let addr = SocketAddrV6::from(addr);
            println!("interface {:?}: {addr}", i.interface_name);
        } else {
            println!("interface {:?}: no ipv6 addr", i.interface_name);
        }
    }
    println!("---");

    let mut listen_addr = addr_for_interface(&args.listen_interface)?;
    listen_addr.set_port(args.listen_port);

    let mut sockets = Vec::with_capacity(args.interfaces.len());
    for interface in args.interfaces {
        let scope_id = nix::net::if_::if_nametoindex(interface.as_str())
            .with_context(|| {
                format!("failed to look up interface {interface:?}")
            })?;

        let mut iface_listen_addr = listen_addr;
        iface_listen_addr.set_scope_id(scope_id);

        println!("binding socket to {}", iface_listen_addr);
        let sock = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            None,
        )
        .context("failed to create socket")?;
        sock.set_reuse_address(true).context("failed to set reuse address")?;
        sock.bind(&iface_listen_addr.into()).context("failed to bind")?;
        let socket = UdpSocket::from_std(sock.into())
            .context("failed to convert socket to tokio")?;

        sockets.push((socket, interface, scope_id));
    }

    for (_socket, _interface, scope_id) in &sockets {
        let mut addr = args.discovery_addr;
        addr.set_scope_id(*scope_id);

        for (socket, interface, _scope_id) in &sockets {
            println!("contacting {addr} on socket for {interface}");

            match try_discover(&socket, addr).await {
                Ok(()) => (),
                Err(err) => println!("{err}"),
            }
        }
    }
    /*
    println!("binding socket to {}", listen_addr);
    let socket = UdpSocket::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind to {listen_addr}"))?;

    let mut buf = [0; gateway_messages::MAX_SERIALIZED_SIZE];

    for interface in args.interfaces {
        let mut addr = args.discovery_addr;
        addr.set_scope_id(scope_id);
        println!("contacting {addr}");

        let request = Message {
            header: Header { version: version::V2, message_id: 1 },
            kind: MessageKind::MgsRequest(MgsRequest::Discover),
        };

        let n = gateway_messages::serialize(&mut buf, &request).unwrap();
        let out = &buf[..n];

        let sent =
            socket.send_to(out, addr).await.context("send_to() failed")?;
        assert_eq!(n, sent);

        let result = match tokio::time::timeout(
            Duration::from_secs(3),
            socket.recv_from(&mut buf),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                println!("timed out waiting for reply");
                continue;
            }
        };

        let (recvd, src_addr) = match result {
            Ok((n, src_addr)) => (&buf[..n], src_addr),
            Err(err) => {
                println!("error receiving: {err}");
                continue;
            }
        };

        let (message, _) = gateway_messages::deserialize::<Message>(recvd)
            .with_context(|| {
                format!("failed to deserialize response {recvd:?}")
            })?;

        println!("got response from {src_addr}: {message:?}");
    }
    */

    Ok(())
}
