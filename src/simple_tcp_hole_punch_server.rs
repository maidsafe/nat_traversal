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

//! # `nat_traversal`
//! NAT traversal utilities.

use std::io;
use std::io::{Read, Write};
use std::net::{TcpStream, TcpListener};
use std::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net;

use maidsafe_utilities::serialisation::serialise;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use w_result::{WResult, WOk, WErr};
use socket_addr::SocketAddr;
use ip::SocketAddrExt;

use listener_message;
use socket_utils;
use mapping_context::MappingContext;
use mapped_tcp_socket::{MappedTcpSocket, MappedTcpSocketNewError, MappedTcpSocketMapWarning};

const TCP_RW_TIMEOUT: u64 = 20;

/// RAII type for a hole punch server which speaks the simple hole punching protocol.
pub struct SimpleTcpHolePunchServer<'a> {
    // TODO(canndrew): Use this to refresh our external addrs.
    _mapping_context: &'a MappingContext,
    stop_flag: Arc<AtomicBool>,
    local_addr: net::SocketAddr,
    _raii_joiner: RaiiThreadJoiner,
    known_endpoints: Vec<SocketAddr>,
}

quick_error! {
    #[derive(Debug)]
    /// Errors returned by SimpleTcpHolePunchServer::new
    pub enum SimpleTcpHolePunchServerNewError {
        /// Error creating a mapped tcp socket to listen on.
        CreateMappedSocket {
            err: MappedTcpSocketNewError } {
            description("Error creating a mapped tcp socket to listen on.")
            display("Error creating a mapped tcp socket to listen on: {}", err)
            cause(err)
        }
        Listen { err: io::Error } {
            description("Error listening on socket.")
            display("Error listening on socket: {}", err)
            cause(err)
        }
        SocketLocalAddr { err: io::Error} {
            description("Error getting local address of listening socket.")
            display("Error getting local address of listening socket: {}", err)
            cause(err)
        }
    }
}

impl<'a> SimpleTcpHolePunchServer<'a> {
    /// Create a new server. This will spawn a background thread which will serve requests until
    /// the server is dropped.
    pub fn new(mapping_context: &'a MappingContext)
        -> WResult<SimpleTcpHolePunchServer<'a>,
                   MappedTcpSocketMapWarning,
                   SimpleTcpHolePunchServerNewError>
    {
        let (mapped_socket, warnings) = match MappedTcpSocket::new(mapping_context) {
            WOk(mapped_socket, warnings) => (mapped_socket, warnings),
            WErr(e) => {
                return WErr(SimpleTcpHolePunchServerNewError::CreateMappedSocket { err: e });
            }
        };

        let tcp_socket = mapped_socket.socket;
        let stop_flag = Arc::new(AtomicBool::new(false));
        let cloned_stop_flag = stop_flag.clone();

        let tcp_listener = match tcp_socket.listen(128) {
            Ok(tcp_listener) => tcp_listener,
            Err(e) => return WErr(SimpleTcpHolePunchServerNewError::Listen { err: e }),
        };

        let mut local_addr = None;
        let unrestricted_endpoints = mapped_socket.endpoints.into_iter().filter_map(|msa| {
            let addr = msa.addr;
            if socket_utils::is_loopback(&SocketAddrExt::ip(&*addr)) {
                local_addr = Some(addr);
                return None;
            };
            match msa.nat_restricted {
                false => Some(addr),
                true => None,
            }
        }).collect();
        let local_addr = match local_addr {
            Some(local_addr) => *local_addr,
            None => {
                match tcp_listener.local_addr() {
                    Ok(local_addr) => local_addr,
                    Err(e) => return WErr(SimpleTcpHolePunchServerNewError::SocketLocalAddr { err: e }),
                }
            },
        };

        let raii_joiner = RaiiThreadJoiner::new(thread!("SimpleTcpHolePunchServer", move || {
            Self::run(tcp_listener, cloned_stop_flag);
        }));

        WOk(SimpleTcpHolePunchServer {
            _mapping_context: mapping_context,
            stop_flag: stop_flag,
            _raii_joiner: raii_joiner,
            local_addr: local_addr,
            known_endpoints: unrestricted_endpoints,
        }, warnings)
    }

    fn run(tcp_listener: TcpListener,
           stop_flag: Arc<AtomicBool>) {

        while !stop_flag.load(Ordering::SeqCst) {
            if let Ok((mut stream, peer_addr)) = tcp_listener.accept() {
                let _ = thread!("SimpleTcpHolePunchServer::run", move || {
                    match stream.set_write_timeout(Some(Duration::from_secs(TCP_RW_TIMEOUT))) {
                        Ok(()) => (),
                        Err(_) => return,
                    };
                    match stream.set_read_timeout(Some(Duration::from_secs(TCP_RW_TIMEOUT))) {
                        Ok(()) => (),
                        Err(_) => return,
                    };
                    let mut read_buf = [0; 1024];
                    let bytes_read = match stream.read(&mut read_buf) {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    if read_buf[..bytes_read] != listener_message::REQUEST_MAGIC_CONSTANT {
                        return;
                    }

                    let resp = listener_message::EchoExternalAddr {
                        external_addr: SocketAddr(peer_addr),
                    };

                    let _ = stream.write(&unwrap_result!(serialise(&resp)));
                });
            }
        }
    }

    /// Get the external addresses of this server to be shared with peers.
    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.known_endpoints.clone()
    }
}

impl<'a> Drop for SimpleTcpHolePunchServer<'a> {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        // Unblock the acceptor.
        let _ = TcpStream::connect(self.local_addr);
    }
}

