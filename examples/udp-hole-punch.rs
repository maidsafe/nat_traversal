#[macro_use]
extern crate maidsafe_utilities;
extern crate nat_traversal;
extern crate w_result;
extern crate rustc_serialize;
extern crate socket_addr;

use std::net::ToSocketAddrs;

use socket_addr::SocketAddr;
use nat_traversal::{MappingContext, gen_rendezvous_info, MappedUdpSocket, PunchedUdpSocket};
use w_result::{WOk, WErr};

fn main() {
    println!("This example allows you to connect to two hosts over UDP through NATs and firewalls.");

    // First, we must create a mapping context.
    let mapping_context = match MappingContext::new() {
        WOk(mapping_context, warnings) => {
            for warning in warnings {
                println!("Warning when creating mapping context: {}", warning);
            }
            mapping_context
        }
        WErr(e) => {
            println!("Error creating mapping context: {}", e);
            println!("Exiting.");
            return;
        }
    };

    // Now we can register a set of external hole punching servers that may be needed to complete
    // the hole punching.
    loop {
        println!("");
        println!("Enter the socket addresses of a simple hole punching server or hit return for none.");
        println!("");
        let mut addr_str = String::new();
        match std::io::stdin().read_line(&mut addr_str) {
            Ok(_) => (),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    println!("Exiting.");
                    return;
                }
                println!("IO error reading stdin: {}", e);
                return;
            },
        };
        let addr_str = addr_str.trim();
        if addr_str == "" {
            break;
        }
        let mut addrs = match addr_str.to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(e) => {
                println!("Error parsing socket address: {}", e);
                continue;
            },
        };
        let addr = match addrs.next() {
            Some(addr) => SocketAddr(addr),
            None => {
                println!("Invalid value");
                continue;
            }
        };
        println!("Registering address: {:#?}", addr);
        mapping_context.add_simple_servers(vec![addr]);
    }

    // Now we use our context to create a mapped udp socket.
    let mapped_socket = match MappedUdpSocket::new(&mapping_context) {
        WOk(mapped_socket, warnings) => {
            for warning in warnings {
                println!("Warning when mapping socket: {}", warning);
            }
            mapped_socket
        },
        WErr(e) => {
            println!("IO error mapping socket: {}", e);
            println!("Exiting.");
            return;
        }
    };

    // A MappedUdpSocket is just a socket and set of known endpoints of the socket;
    let MappedUdpSocket { socket, endpoints } = mapped_socket;
    println!("Created a socket. It's endpoints are: {:#?}", endpoints);

    // Now we use the endpoints to create a rendezvous info pair
    let (our_priv_info, our_pub_info) = gen_rendezvous_info(endpoints);

    // Now we exchange our public rendezvous info with the remote peer out-of-band somehow. Yes, to
    // connect to the peer you already need to be able to communicate with them. Yes, network
    // address translation sucks.
    println!("Your public rendezvous info is:");
    println!("");
    println!("{}", unwrap_result!(rustc_serialize::json::encode(&our_pub_info)));
    println!("");

    let their_pub_info;
    loop {
        println!("Paste the peer's pub rendezvous info below and when you are ready to initiate");
        println!("the connection hit return. The peer must initiate their side of the connection");
        println!("at the same time.");
        println!("");

        let mut info_str = String::new();
        match std::io::stdin().read_line(&mut info_str) {
            Ok(_) => (),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    println!("Exiting.");
                    return;
                }
                println!("IO error reading stdin: {}", e);
                return;
            },
        };
        match rustc_serialize::json::decode(&info_str) {
            Ok(info) => {
                their_pub_info = info;
                break;
            },
            Err(e) => {
                println!("Error decoding their public rendezvous info: {}", e);
                println!("Push sure to paste their complete info all in one line.");
            }
        }
    };

    // Now we use the socket, our private rendezvous info and their public rendezvous info to
    // complete the connection.
    let punched_socket = match PunchedUdpSocket::punch_hole(socket, our_priv_info, their_pub_info) {
        WOk(punched_socket, warnings) => {
            for warning in warnings {
                println!("Warning when punching hole: {}", warning);
            }
            punched_socket
        },
        WErr(e) => {
            println!("IO error punching udp socket: {}", e);
            println!("Exiting.");
            return;
        },
    };

    // A PunchedUdpSocket is just a socket and an address that we should have unrestricted
    // communication to.
    let PunchedUdpSocket { socket, peer_addr } = punched_socket;

    let recv_socket = match socket.try_clone() {
        Ok(recv_socket) => recv_socket,
        Err(e) => {
            println!("Failed to clone udp socket: {}", e);
            println!("Exiting.");
            return;
        }
    };

    // Now we can chat to the peer!
    println!("Connected! You can now chat to your buddy. ^D to exit.");

    let _ = thread!("recv and print", move || {
        let mut buf = [0u8; 1024];
        loop {
            let (n, addr) = match recv_socket.recv_from(&mut buf[..]) {
                Ok(x) => x,
                Err(e) => {
                    println!("IO error receiving from udp socket: {}", e);
                    //return;
                    continue;
                }
            };
            if addr != peer_addr.0 {
                continue;
            }
            match std::str::from_utf8(&buf[..n]) {
                Ok(s) => println!("{}", s),
                Err(e) => println!("Peer sent invalid utf8 data. Error: {}", e),
            };
        }
    });

    let mut line;
    loop {
        line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(_) => (),
            Err(e) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    println!("Error reading from stdin: {}", e);
                }
                println!("Exiting.");
                return;
            }
        };
        match socket.send_to(line.as_bytes(), peer_addr.0) {
            Ok(_) => (),
            Err(e) => {
                println!("Error writing to udp socket: {}", e);
                println!("Exiting.");
                return;
            }
        };
    }
}

