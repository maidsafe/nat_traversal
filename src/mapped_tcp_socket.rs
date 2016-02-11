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

use std::net::TcpStream;

use net2;

use mapping_context::MappingContext;
use mapped_socket_addr::MappedSocketAddr;
use rendezvous_info::{PrivRendezvousInfo, PubRendezvousInfo};

/// A tcp socket for which we know our external endpoints.
pub struct MappedTcpSocket {
    /// A bound, but neither listening or connected tcp socket. The socket is
    /// bound to be reuseable (ie. SO_REUSEADDR is set as is SO_REUSEPORT on
    /// unix).
    pub socket: net2::TcpBuilder,
    /// The known endpoints of this socket.
    pub endpoints: Vec<MappedSocketAddr>,
}

impl MappedTcpSocket {
    /// Map an existing tcp socket. The socket must not bound or connected. This
    /// function will set the options to make the socket address reuseable
    /// before binding it.
    pub fn map(_socket: net2::TcpBuilder, _mc: &MappingContext)
               -> MappedTcpSocket {
        unimplemented!();
    }

    /// Create a new `MappedTcpSocket`
    pub fn new(_mc: &MappingContext) -> MappedTcpSocket {
        unimplemented!();
    }
}

/// Perform a tcp rendezvous connect. `socket` should have been obtained from a
/// `MappedTcpSocket`.
pub fn tcp_punch_hole(_socket: net2::TcpBuilder,
                      _our_priv_rendezvous_info: PrivRendezvousInfo,
                      _their_pub_rendezvous_info: PubRendezvousInfo)
                      -> TcpStream {
    unimplemented!();
}
