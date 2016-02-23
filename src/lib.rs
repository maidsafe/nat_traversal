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

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/nat_traversal/")]

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

// TODO(canndrew): Remove this once this: https://github.com/tailhook/quick-error/issues/18
// is fixed.
#![allow(missing_docs)]

extern crate cbor;
extern crate net2;
extern crate rand;
extern crate rustc_serialize;
extern crate time;
extern crate void;
#[macro_use]
extern crate maidsafe_utilities;
extern crate igd;
extern crate socket_addr;
extern crate get_if_addrs;
extern crate w_result;
extern crate ip;
#[allow(unused_extern_crates)] // Needed because the crate is only used for macros
#[macro_use]
extern crate quick_error;

pub use mapping_context::{MappingContext, MappingContextNewError, MappingContextNewWarning};
pub use mapped_socket_addr::MappedSocketAddr;
pub use rendezvous_info::{PrivRendezvousInfo, PubRendezvousInfo,
                         gen_rendezvous_info};
pub use mapped_udp_socket::{MappedUdpSocket, MappedUdpSocketMapError,
                            MappedUdpSocketMapWarning, MappedUdpSocketNewError};
pub use punched_udp_socket::{PunchedUdpSocket, filter_udp_hole_punch_packet};
pub use mapped_tcp_socket::{MappedTcpSocket, tcp_punch_hole};
pub use simple_udp_hole_punch_server::{SimpleUdpHolePunchServer, SimpleUdpHolePunchServerNewError};

mod mapping_context;
mod mapped_socket_addr;
mod rendezvous_info;
mod mapped_udp_socket;
mod punched_udp_socket;
mod mapped_tcp_socket;
mod simple_udp_hole_punch_server;
mod socket_utils;
mod listener_message;

