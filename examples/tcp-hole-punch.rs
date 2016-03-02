// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! TCP hole punch example.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, clippy_pedantic))]

#[allow(unused_extern_crates)]
#[macro_use]
extern crate maidsafe_utilities;
extern crate nat_traversal;
extern crate w_result;
extern crate rustc_serialize;
extern crate socket_addr;

use std::net::ToSocketAddrs;
use std::io::{Read, Write};

use socket_addr::SocketAddr;
use nat_traversal::{MappingContext, gen_rendezvous_info, MappedTcpSocket, tcp_punch_hole};
use w_result::{WOk, WErr};

fn main() {
    println!("This example allows you to connect to two hosts over TCP through NATs and firewalls.");

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
        mapping_context.add_simple_tcp_servers(vec![addr]);
    }

    // Now we use our context to create a mapped tcp socket.
    let mapped_socket = match MappedTcpSocket::new(&mapping_context) {
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

    // A MappedTcpSocket is just a socket and set of known endpoints of the socket;
    let MappedTcpSocket { socket, endpoints } = mapped_socket;
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
    let mut stream = match tcp_punch_hole(socket, our_priv_info, their_pub_info) {
        WOk(punched_socket, warnings) => {
            for warning in warnings {
                println!("Warning when punching hole: {}", warning);
            }
            punched_socket
        },
        WErr(e) => {
            println!("Error punching tcp socket: {}", e);
            println!("Exiting.");
            return;
        },
    };

    let mut recv_stream = match stream.try_clone() {
        Ok(recv_stream) => recv_stream,
        Err(e) => {
            println!("Failed to clone tcp stream: {}", e);
            println!("Exiting.");
            return;
        }
    };

    // Now we can chat to the peer!
    println!("Connected! You can now chat to your buddy. ^D to exit.");

    let _ = thread!("recv and print", move || {
        let mut buf = [0u8; 1024];
        loop {
            let n = match recv_stream.read(&mut buf[..]) {
                Ok(n) => n,
                Err(e) => {
                    println!("IO error receiving from tcp socket: {}", e);
                    //return;
                    continue;
                }
            };
            if n == 0 {
                println!("Disconnected.");
                return;
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
        match stream.write_all(line.as_bytes()) {
            Ok(()) => (),
            Err(e) => {
                println!("Error writing to tcp stream: {}", e);
                println!("Exiting.");
                return;
            }
        };
    }
}

