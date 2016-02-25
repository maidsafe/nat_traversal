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

use std::sync::RwLock;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::thread;
use std::time::Duration;

use igd;
use socket_addr::SocketAddr;
use w_result::{WResult, WOk, WErr};
use get_if_addrs;
use void::Void;

/// You need to create a `MappingContext` before doing any socket mapping. This
/// `MappingContext` should ideally be kept throughout the lifetime of the
/// program. Internally it caches a addresses of UPnP servers and hole punching
/// servers.
pub struct MappingContext {
    interfaces_v4: RwLock<Vec<InterfaceV4>>,
    interfaces_v6: RwLock<Vec<InterfaceV6>>,
    simple_udp_servers: RwLock<Vec<SocketAddr>>,
    simple_tcp_servers: RwLock<Vec<SocketAddr>>,
}

#[derive(Clone)]
pub struct InterfaceV4 {
    pub gateway: Option<igd::Gateway>,
    pub addr: Ipv4Addr,
}

// TODO(canndrew): Can we support IGD on ipv6?
#[derive(Clone)]
pub struct InterfaceV6 {
    pub addr: Ipv6Addr,
}

quick_error! {
    #[derive(Debug)]
    pub enum MappingContextNewError {
        /// Failed to list the local machine's network interfaces.
        ListInterfaces {
            err:io::Error,
        } {
            description("Failed to list the local machine's network interfaces")
            display("Failed to list the local machines's network interfaces \
                     get_if_addrs returned an error: {}", err)
            cause(err)
        }
        /// Failed to spawn a thread.
        SpawnThread {
            err: io::Error
        } {
            description("Failed to spawn a thread")
            display("Failed to spawn a thread. \
                     thread::spawn returned an error: {}", err)
            cause(err)
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum MappingContextNewWarning {
        /// Error finding IGD gateway. `if_name` and `if_addr` indicate the network interface being
        /// searched from when this error was raised.
        SearchGateway {
            if_name: String,
            if_addr: Ipv4Addr,
            err: igd::SearchError
        } {
            description("Failed to find IGD gateway")
            display("Failed to find an IGD gateway on network interface {} {}. \
                     igd::search_gateway_from_timeout returned an error: {}",
                     if_name, if_addr, err)
            cause(err)
        }
    }
}

impl MappingContext {
    /// Create a new mapping context. This will block breifly while it searches
    /// the network for UPnP servers.
    pub fn new() -> WResult<MappingContext, MappingContextNewWarning, MappingContextNewError> {
        let interfaces = match get_if_addrs::get_if_addrs() {
            Ok(if_addrs) => if_addrs,
            Err(e) => return WErr(MappingContextNewError::ListInterfaces { err: e }),
        };
        let mut interfaces_v4 = Vec::new();
        let mut interfaces_v6 = Vec::new();
        let mut warnings = Vec::new();
        let mut search_threads = Vec::new();
        for interface in interfaces {
            let addr_v4 = match interface.addr {
                get_if_addrs::IfAddr::V4(v4_addr) => {
                    v4_addr.ip
                },
                get_if_addrs::IfAddr::V6(v6_addr) => {
                    interfaces_v6.push(InterfaceV6 {
                        addr: v6_addr.ip,
                    });
                    continue;
                },
            };
            // TODO(canndrew): use is_loopback when it's stable
            //if addr.is_loopback() {
            if addr_v4.octets()[0] == 127 {
                interfaces_v4.push(InterfaceV4 {
                    gateway: None,
                    addr: addr_v4,
                });
                continue;
            };
            let if_name = interface.name;
            search_threads.push(thread::Builder::new()
                                                .name(From::from("IGD search"))
                                                .spawn(move || -> WResult<_, _, Void> {
                let mut warnings = Vec::new();
                let gateway = match igd::search_gateway_from_timeout(addr_v4, Duration::from_secs(1)) {
                    Ok(gateway) => Some(gateway),
                    Err(e) => {
                        warnings.push(MappingContextNewWarning::SearchGateway {
                            if_name: if_name,
                            if_addr: addr_v4,
                            err: e,
                        });
                        None
                    },
                };
                WOk(InterfaceV4 {
                    gateway: gateway,
                    addr: addr_v4,
                }, warnings)
            }));
        };

        for search_thread in search_threads {
            match search_thread {
                Err(e) => return WErr(MappingContextNewError::SpawnThread { err: e }),
                Ok(jh) => {
                    // If the child thread panicked, propogate the panic.
                    let res = unwrap_result!(jh.join());
                    match res {
                        WErr(e) => match e {},
                        WOk(interface, ws) => {
                            interfaces_v4.push(interface);
                            warnings.extend(ws);
                        }
                    }
                }
            }
        }
        let mc = MappingContext {
            interfaces_v4: RwLock::new(interfaces_v4),
            interfaces_v6: RwLock::new(interfaces_v6),
            simple_udp_servers: RwLock::new(Vec::new()),
            simple_tcp_servers: RwLock::new(Vec::new()),
        };
        WOk(mc, warnings)
    }

    /// Inform the context about external servers that speak the UDP simple hole punch server
    /// protocol.
    pub fn add_simple_udp_servers<S>(&self, servers: S)
        where S: IntoIterator<Item=SocketAddr>
    {
        let mut s = unwrap_result!(self.simple_udp_servers.write());
        s.extend(servers)
    }

    /// Inform the context about external servers that speak the TCP simple hole punch server
    /// protocol.
    pub fn add_simple_tcp_servers<S>(&self, servers: S)
        where S: IntoIterator<Item=SocketAddr>
    {
        let mut s = unwrap_result!(self.simple_tcp_servers.write());
        s.extend(servers)
    }
}

pub fn interfaces_v4(mc: &MappingContext) -> Vec<InterfaceV4> {
    unwrap_result!(mc.interfaces_v4.read()).clone()
}

pub fn interfaces_v6(mc: &MappingContext) -> Vec<InterfaceV6> {
    unwrap_result!(mc.interfaces_v6.read()).clone()
}

pub fn simple_udp_servers(mc: &MappingContext) -> Vec<SocketAddr> {
    unwrap_result!(mc.simple_udp_servers.read()).clone()
}

pub fn simple_tcp_servers(mc: &MappingContext) -> Vec<SocketAddr> {
    unwrap_result!(mc.simple_tcp_servers.read()).clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_mapping_context() {
        let _ = unwrap_result!(MappingContext::new().result_discard());
    }
}

