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
use std::net::UdpSocket;
use std::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use maidsafe_utilities::serialisation::serialise;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use w_result::{WResult, WOk, WErr};

use socket_addr::SocketAddr;
use listener_message;

use mapping_context::MappingContext;
use mapped_udp_socket::{MappedUdpSocket, MappedUdpSocketNewError, MappedUdpSocketMapWarning};

const UDP_READ_TIMEOUT_SECS: u64 = 2;

/// RAII type for a hole punch server which speaks the simple hole punching protocol.
pub struct SimpleUdpHolePunchServer<T: AsRef<MappingContext>> {
    // TODO(canndrew): Use this to refresh our external addrs.
    _mapping_context: T,
    stop_flag: Arc<AtomicBool>,
    _raii_joiner: RaiiThreadJoiner,
    known_endpoints: Vec<SocketAddr>,
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

impl From<SimpleUdpHolePunchServerNewError> for io::Error {
    fn from(e: SimpleUdpHolePunchServerNewError) -> io::Error {
        let err_str = format!("{}", e);
        let kind = match e {
            SimpleUdpHolePunchServerNewError::CreateMappedSocket { err } => {
                let err: io::Error = From::from(err);
                err.kind()
            },
            SimpleUdpHolePunchServerNewError::SetSocketTimeout { err } => err.kind(),
        };
        io::Error::new(kind, err_str)
    }
}

impl<T: AsRef<MappingContext>> SimpleUdpHolePunchServer<T> {
    /// Create a new server. This will spawn a background thread which will serve requests until
    /// the server is dropped.
    pub fn new(mapping_context: T)
        -> WResult<SimpleUdpHolePunchServer<T>,
                   MappedUdpSocketMapWarning,
                   SimpleUdpHolePunchServerNewError>
    {
        let (mapped_socket, warnings) = match MappedUdpSocket::new(mapping_context.as_ref()) {
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

        let unrestricted_endpoints = mapped_socket.endpoints.into_iter().filter_map(|msa| {
            match msa.nat_restricted {
                false => Some(msa.addr),
                true => None,
            }
        }).collect();
        WOk(SimpleUdpHolePunchServer {
            _mapping_context: mapping_context,
            stop_flag: stop_flag,
            _raii_joiner: raii_joiner,
            known_endpoints: unrestricted_endpoints,
        }, warnings)
    }

    fn run(udp_socket: UdpSocket,
           stop_flag: Arc<AtomicBool>) {
        let mut read_buf = [0; 1024];

        while !stop_flag.load(Ordering::SeqCst) {
            if let Ok((bytes_read, peer_addr)) = udp_socket.recv_from(&mut read_buf) {
                if read_buf[..bytes_read] != listener_message::REQUEST_MAGIC_CONSTANT {
                    continue;
                }

                let resp = listener_message::EchoExternalAddr {
                    external_addr: SocketAddr(peer_addr.clone()),
                };

                let _ = udp_socket.send_to(&unwrap_result!(serialise(&resp)),
                                           peer_addr);
            }
        }
    }

    /// Get the external addresses of this server to be shared with peers.
    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.known_endpoints.clone()
    }
}

impl<T: AsRef<MappingContext>> Drop for SimpleUdpHolePunchServer<T> {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}
