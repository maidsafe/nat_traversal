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
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use get_if_addrs;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use maidsafe_utilities::thread::RaiiThreadJoiner;
use rand;
use sodiumoxide::crypto::sign::PublicKey;

use socket_addr::SocketAddr;
use listener_message;

use mapping_context::MappingContext;
use mapped_socket_addr::MappedSocketAddr;

const UDP_READ_TIMEOUT_SECS: u64 = 2;

/// RAII type for a hole punch server which speaks the simple hole punching protocol.
pub struct SimpleUdpHolePunchServer<'a> {
    mapping_context: &'a MappingContext,
    stop_flag: Arc<AtomicBool>,
    _raii_joiner: RaiiThreadJoiner,
}

impl<'a> SimpleUdpHolePunchServer<'a> {
    /// Create a new server. This will spawn a background thread which will serve requests until
    /// the server is dropped.
    pub fn new(mapping_context: &'a MappingContext)
        -> io::Result<SimpleUdpHolePunchServer<'a>> {
        let udp_socket = try!(UdpSocket::bind("0.0.0.0:0"));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let cloned_stop_flag = stop_flag.clone();

        try!(udp_socket.set_read_timeout(Some(Duration::from_secs(UDP_READ_TIMEOUT_SECS))));
        let port = try!(udp_socket.local_addr()).port();

        const MAX_READ_SIZE: usize = 1024;

        let mut read_buf = [0; MAX_READ_SIZE];

        let raii_joiner = RaiiThreadJoiner::new(thread!("SimpleUdpHolePunchServer", move || {
            Self::run(udp_socket, cloned_stop_flag);
        }));

        Ok(SimpleUdpHolePunchServer {
            mapping_context: mapping_context,
            stop_flag: stop_flag,
            _raii_joiner: raii_joiner,
        })
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
    pub fn addresses(&self) -> Vec<MappedSocketAddr> {
        // TODO:

        // The idea was it would need to know it's own external IP and whether
        // it has an open port or not.  And it might occasionally need to make
        // sure its port is still mapped. ie still open on the router

        // So it wants to find external ports with `nat_restricted ==
        // false`. Those are the only ones worth sharing with other peers. it
        // can get those by doing upnp for example
        unimplemented!();
    }
}

impl<'a> Drop for SimpleUdpHolePunchServer<'a> {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}
