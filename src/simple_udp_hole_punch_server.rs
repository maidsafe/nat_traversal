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
use std::net;
use std::net::UdpSocket;
use std::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use maidsafe_utilities::serialisation::{deserialise, serialise};
use maidsafe_utilities::thread::RaiiThreadJoiner;
use w_result::{WResult, WOk, WErr};

use socket_addr::SocketAddr;
use listener_message::{ListenerRequest, ListenerResponse};

use mapping_context::MappingContext;
use mapped_socket_addr::MappedSocketAddr;
use mapped_udp_socket::{MappedUdpSocket, MappedUdpSocketNewError, MappedUdpSocketMapWarning};

const UDP_READ_TIMEOUT_SECS: u64 = 2;

/// RAII type for a hole punch server which speaks the simple hole punching protocol.
pub struct SimpleUdpHolePunchServer<'a> {
    // TODO(canndrew): Use this to refresh our external addrs.
    _mapping_context: &'a MappingContext,
    stop_flag: Arc<AtomicBool>,
    _raii_joiner: RaiiThreadJoiner,
    known_endpoints: Vec<MappedSocketAddr>,
}

quick_error! {
    #[derive(Debug)]
    /// Errors returned by SimpleUdpHolePunchServer::new
    pub enum SimpleUdpHolePunchServerNewError {
        /// Error creating a mapped udp socket to listen on.
        CreateMappedSocket {
            err: MappedUdpSocketNewError } {
            description("Error creating a mapped udp socket to listen on.")
            display("Error creating a mapped udp socket to listen on: {}", err)
            cause(err)
        }
        /// Error setting the timeout on the server's listening socket.
        SetSocketTimeout {
            err: io::Error
        } {
            description("Error setting the timeout on the server's listening socket.")
            display("Error setting the timeout on the server's listening socket: {}.", err)
            cause(err)
        }
    }
}

impl<'a> SimpleUdpHolePunchServer<'a> {
    /// Create a new server. This will spawn a background thread which will serve requests until
    /// the server is dropped.
    pub fn new(mapping_context: &'a MappingContext)
        -> WResult<SimpleUdpHolePunchServer<'a>,
                   MappedUdpSocketMapWarning,
                   SimpleUdpHolePunchServerNewError>
    {
        let (mapped_socket, warnings) = match MappedUdpSocket::new(mapping_context) {
            WOk(mapped_socket, warnings) => (mapped_socket, warnings),
            WErr(e) => {
                return WErr(SimpleUdpHolePunchServerNewError::CreateMappedSocket { err: e });
            }
        };

        let udp_socket = mapped_socket.socket;
        let stop_flag = Arc::new(AtomicBool::new(false));
        let cloned_stop_flag = stop_flag.clone();

        match udp_socket.set_read_timeout(Some(Duration::from_secs(UDP_READ_TIMEOUT_SECS))) {
            Ok(()) => (),
            Err(e) => {
                return WErr(SimpleUdpHolePunchServerNewError::SetSocketTimeout { err: e })
            }
        };

        let raii_joiner = RaiiThreadJoiner::new(thread!("SimpleUdpHolePunchServer", move || {
            Self::run(udp_socket, cloned_stop_flag);
        }));

        WOk(SimpleUdpHolePunchServer {
            _mapping_context: mapping_context,
            stop_flag: stop_flag,
            _raii_joiner: raii_joiner,
            known_endpoints: mapped_socket.endpoints,
        }, warnings)
    }

    fn run(udp_socket: UdpSocket,
           stop_flag: Arc<AtomicBool>) {
        let mut read_buf = [0; 1024];

        while !stop_flag.load(Ordering::SeqCst) {
            if let Ok((bytes_read, peer_addr)) = udp_socket.recv_from(&mut read_buf) {
                if let Ok(msg) = deserialise::<ListenerRequest>(&read_buf[..bytes_read]) {
                    SimpleUdpHolePunchServer::handle_request(msg,
                                                             &udp_socket,
                                                             peer_addr);
                } else if let Ok(msg) = deserialise::<ListenerResponse>(&read_buf[..bytes_read]) {
                    SimpleUdpHolePunchServer::handle_response(msg,
                                                              &udp_socket,
                                                              peer_addr);
                }
            }
        }
    }

    fn handle_request(msg: ListenerRequest,
                      udp_socket: &UdpSocket,
                      peer_addr: net::SocketAddr) {
        match msg {
            ListenerRequest::EchoExternalAddr => {
                let resp = ListenerResponse::EchoExternalAddr {
                    external_addr: SocketAddr(peer_addr.clone()),
                };

                let _ = udp_socket.send_to(&unwrap_result!(serialise(&resp)), peer_addr);
            }
        }
    }

    fn handle_response(_msg: ListenerResponse,
                       _udp_socket: &UdpSocket,
                       _peer_addr: net::SocketAddr) {
        // This is currently unimplemented as SimpleUdpHolePunchServer should not have made
        // any request - it is supposed to get requests, not make one
        match _msg {
            ListenerResponse::EchoExternalAddr { .. } => unimplemented!(),
        }
    }

    /// Get the external addresses of this server to be shared with peers.
    pub fn addresses(&self) -> Vec<MappedSocketAddr> {
        // TODO:

        // The idea was it would need to know it's own external IP and whether
        // it has an open port or not.  And it might occasionally need to make
        // sure its port is still mapped. ie still open on the router

        // So it wants to find external ports with `nat_restricted ==
        // false`. Those are the only ones worth sharing with other peers. it
        // can get those by doing upnp for example

        self.known_endpoints.clone()
    }
}

impl<'a> Drop for SimpleUdpHolePunchServer<'a> {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}
