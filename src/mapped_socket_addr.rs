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

use socket_addr::SocketAddr;

/// A socket address obtained through some mapping technique.
#[derive(Debug, PartialEq, Eq, Clone, RustcEncodable, RustcDecodable)]
pub struct MappedSocketAddr {
    /// The mapped address
    pub addr: SocketAddr,

    /// Indicated that hole punching needs to be used for an external client to connect to this
    /// address. `nat_restricted` will not be set if this is a fully mapped address such as the
    /// external address of a full-cone NAT or one obtained through UPnP.
    pub nat_restricted: bool,
}

