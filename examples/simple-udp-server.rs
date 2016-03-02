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

//! Simple service example.

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

extern crate nat_traversal;
extern crate w_result;

use nat_traversal::{MappingContext, SimpleUdpHolePunchServer};
use w_result::{WOk, WErr};

fn main() {
    println!("The example runs a simple rendezvous server that peers can use to connect to each other with");

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

    // Now we create the server.
    let simple_server = match SimpleUdpHolePunchServer::new(&mapping_context) {
        WOk(simple_server, warnings) => {
            for warning in warnings {
                println!("Warning when creating simple server: {}", warning);
            }
            simple_server
        },
        WErr(e) => {
            println!("Error creating simple server: {}", e);
            println!("Exiting.");
            return;
        }
    };

    // Now we print the servers known addresses
    let addresses = simple_server.addresses();
    println!("Server addresses: {:#?}", addresses);

    std::thread::park();
}

