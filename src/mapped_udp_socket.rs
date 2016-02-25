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
use std::net;
use std::time::Duration;
use std::collections::HashSet;

use igd;
use time;
use ip::{SocketAddrExt, IpAddr};
use maidsafe_utilities::serialisation::deserialise;
use socket_addr::SocketAddr;
use w_result::{WResult, WOk, WErr};

use listener_message;
use mapping_context;
use mapping_context::MappingContext;
use mapped_socket_addr::MappedSocketAddr;
use socket_utils;
use socket_utils::RecvUntil;

/// A bound udp socket for which we know our external endpoints.
pub struct MappedUdpSocket {
    /// The socket.
    pub socket: UdpSocket,
    /// The known endpoints of this socket.
    pub endpoints: Vec<MappedSocketAddr>
}

quick_error! {
    /// Errors returned by MappedUdpSocket::map
    #[derive(Debug)]
    pub enum MappedUdpSocketMapError {
        /// Error getting the local address of the socket.
        SocketLocalAddr {
            err: io::Error
        } {
            description("Error getting local address of socket \
                         (have you called bind() on the socket?)")
            display("Error getting local address of socket. \
                     UdpSocket::local_addr returned an error: {}
                     (have you called bind() on the socket?).",
                     err)
            cause(err)
        }
        /// IO error receiving data on the socket.
        RecvError {
            err: io::Error
        } {
            description("IO error receiving data on socket")
            display("IO error receiving data on socket: {}", err)
            cause(err)
        }
        /// IO error sending data on the socket.
        SendError {
            err: io::Error
        } {
            description("IO error sending data on socket")
            display("IO error sending data on socket: {}", err)
            cause(err)
        }
    }
}

quick_error! {
    /// Warnings raised by MappedUdpSocket::map
    #[derive(Debug)]
    pub enum MappedUdpSocketMapWarning {
        /// Error searching for IGD gateway
        FindGateway {
            err: igd::SearchError
        } {
            description("Error searching for IGD gateway")
            display("Error searching for IGD gateway. \
                     igd::search_gateway_from_timeout returned an error: {}",
                     err)
            cause(err)
        }
        /// Error mapping external address and port through IGD gateway. `gateway_addr` is the
        /// address of the IGD gateway that we requested a port mapping from.
        GetExternalPort {
            gateway_addr: net::SocketAddrV4,
            err: igd::AddAnyPortError,
        } {
            description("Error mapping external address and port through IGD \
                         gateway")
            display("Error mapping external address and port through IGD \
                     gateway at address {}. igd::Gateway::get_any_address \
                     returned an error: {}", gateway_addr, err)
            cause(err)
        }
    }
}

quick_error! {
    /// Errors returned by MappedUdpSocket::new
    #[derive(Debug)]
    pub enum MappedUdpSocketNewError {
        /// Error creating new udp socket bound to 0.0.0.0:0
        CreateSocket {
            err: io::Error
        } {
            description("Error creating a new udp socket bound to 0.0.0.0:0")
            display("Error creating a new udp socket bound to 0.0.0.0:0. \
                     UdpSocket::bind returned an IO error: {}", err)
            cause(err)
        }
        /// Error mapping udp socket.
        MapSocket {
            err: MappedUdpSocketMapError
        } {
            description("Error mapping udp socket")
            display("Error mapping udp socket. MappedUdpSocket::map returned \
                     an error: {}", err)
            cause(err)
        }
    }
}

impl MappedUdpSocket {
    /// Map an existing `UdpSocket`.
    pub fn map(socket: UdpSocket, mc: &MappingContext)
               -> WResult<MappedUdpSocket, MappedUdpSocketMapWarning, MappedUdpSocketMapError>
    {
        let mut endpoints = Vec::new();
        let mut warnings = Vec::new();

        // Add the local addresses of this socket for the sake of peers on the name machine or
        // same local network as us.
        let local_addr = match socket.local_addr() {
            Ok(local_addr) => local_addr,
            Err(e) => return WErr(MappedUdpSocketMapError::SocketLocalAddr { err: e })
        };
        match SocketAddrExt::ip(&local_addr) {
            IpAddr::V4(ipv4_addr) => {
                if socket_utils::ipv4_is_unspecified(&ipv4_addr) {
                    // If the socket address is unspecified we add an address for every local
                    // interface. We also ask the interface's IGD gateway (if there is one) for
                    // an address.
                    for iface_v4 in mapping_context::interfaces_v4(&mc) {
                        let local_iface_addr = net::SocketAddrV4::new(iface_v4.addr, local_addr.port());
                        endpoints.push(MappedSocketAddr {
                            addr: SocketAddr(net::SocketAddr::V4(local_iface_addr)),
                            nat_restricted: false,
                        });
                        if let Some(gateway) = iface_v4.gateway {
                            match gateway.get_any_address(igd::PortMappingProtocol::UDP,
                                                          local_iface_addr, 0,
                                                          "rust nat_traversal")
                            {
                                Ok(external_addr) => {
                                    endpoints.push(MappedSocketAddr {
                                        addr: SocketAddr(net::SocketAddr::V4(external_addr)),
                                        nat_restricted: false,
                                    });
                                },
                                Err(e) => {
                                    warnings.push(MappedUdpSocketMapWarning::GetExternalPort {
                                        gateway_addr: gateway.addr,
                                        err: e,
                                    });
                                }
                            }
                        };
                    };
                }
                else {
                    let local_addr_v4 = net::SocketAddrV4::new(ipv4_addr, local_addr.port());
                    endpoints.push(MappedSocketAddr {
                        addr: SocketAddr(net::SocketAddr::V4(local_addr_v4)),
                        nat_restricted: false,
                    });

                    // If the local address is the address of an interface then we can avoid
                    // searching for an IGD gateway, just reuse the search result from when we
                    // found this interface.
                    let mut gateway_opt_opt = None;
                    for iface_v4 in mapping_context::interfaces_v4(&mc) {
                        if iface_v4.addr == ipv4_addr {
                            gateway_opt_opt = Some(iface_v4.gateway);
                            break;
                        }
                    };
                    let gateway_opt = match gateway_opt_opt {
                        Some(gateway_opt) => gateway_opt,
                        // We don't where this local address came from so search for an IGD gateway
                        // at it.
                        None => {
                            match igd::search_gateway_from_timeout(ipv4_addr, Duration::from_secs(1)) {
                                Ok(gateway) => Some(gateway),
                                Err(e) => {
                                    warnings.push(MappedUdpSocketMapWarning::FindGateway {
                                        err: e
                                    });
                                    None
                                }
                            }
                        }
                    };
                    // If we have a gateway, ask it for an external address.
                    if let Some(gateway) = gateway_opt {
                        match gateway.get_any_address(igd::PortMappingProtocol::UDP,
                                                      local_addr_v4, 0,
                                                      "rust nat_traversal")
                        {
                            Ok(external_addr) => {
                                endpoints.push(MappedSocketAddr {
                                    addr: SocketAddr(net::SocketAddr::V4(external_addr)),
                                    nat_restricted: false,
                                });
                            },
                            Err(e) => {
                                warnings.push(MappedUdpSocketMapWarning::GetExternalPort {
                                    gateway_addr: gateway.addr,
                                    err: e,
                                });
                            }
                        }
                    };
                };
            },
            IpAddr::V6(ipv6_addr) => {
                if socket_utils::ipv6_is_unspecified(&ipv6_addr) {
                    // If the socket address is unspecified add an address for every interface.
                    for iface_v6 in mapping_context::interfaces_v6(&mc) {
                        let local_iface_addr = net::SocketAddr::V6(net::SocketAddrV6::new(iface_v6.addr, local_addr.port(), 0, 0));
                        endpoints.push(MappedSocketAddr {
                            addr: SocketAddr(local_iface_addr),
                            nat_restricted: false,
                        });
                    };
                }
                else {
                    endpoints.push(MappedSocketAddr {
                        addr: SocketAddr(net::SocketAddr::V6(net::SocketAddrV6::new(ipv6_addr, local_addr.port(), 0, 0))),
                        nat_restricted: false,
                    });
                }
            },
        };

        const MAX_DATAGRAM_SIZE: usize = 256;

        let send_data = listener_message::REQUEST_MAGIC_CONSTANT;
        let mut simple_servers: HashSet<SocketAddr> = mapping_context::simple_udp_servers(&mc)
                                                                      .into_iter().collect();

        // Ping all the simple servers and waiting for a response.
        let start_time = time::SteadyTime::now();
        let mut deadline = start_time;
        let mut final_deadline = start_time + time::Duration::seconds(2);
        while deadline < final_deadline && simple_servers.len() > 0 {
            deadline = deadline + time::Duration::milliseconds(250);

            // TODO(canndrew): We should limit the number of servers that we send to. If the user
            // has added two thousand servers we really don't want to be pinging all of them. We
            // should be smart about it though and try to ping servers that are on different
            // networks, not just the first ten in the list or something.
            for simple_server in &simple_servers {
                // TODO(canndrew): What should we do if we get a partial write?
                let _ = match socket.send_to(&send_data[..], &**simple_server) {
                    Ok(n) => n,
                    Err(e) => return WErr(MappedUdpSocketMapError::SendError { err: e }),
                };
            };
            let mut recv_data = [0u8; MAX_DATAGRAM_SIZE];
            loop {
                let (read_size, recv_addr) = match socket.recv_until(&mut recv_data[..], deadline) {
                    Ok(Some(res)) => res,
                    Ok(None) => break,
                    Err(e) => return WErr(MappedUdpSocketMapError::RecvError { err: e }),
                };
                if let Ok(listener_message::EchoExternalAddr { external_addr }) =
                       deserialise::<listener_message::EchoExternalAddr>(&recv_data[..read_size]) {
                    // Don't ping this simple server again while mapping this socket.
                    simple_servers.remove(&recv_addr);

                    // If the address that responded to us is global then drop max_attempts to exit
                    // the loop more quickly. The logic here is that global addresses are the ones
                    // that are likely to take the longest to respond and they're all likely to
                    // give us the same address. By contrast, servers on the same subnet as us or
                    // behind the same carrier-level NAT are likely to respond in under a second.
                    // So once we have one global address drop the timeout.

                    // TODO(canndrew): Use IpAddr::is_global when it's available
                    // let is_global = recv_addr.is_global();
                    let is_global = false;
                    if is_global {
                        final_deadline = start_time + time::Duration::seconds(1);
                    };

                    // Add this endpoint if we don't already know about it. We may have found it
                    // through IGD or it may be a local interface.
                    if endpoints.iter().all(|e| e.addr != external_addr) {
                        endpoints.push(MappedSocketAddr {
                            addr: external_addr,
                            // TODO(canndrew): We should consider ways to determine whether this is
                            // actually an restricted port. For now, just assume it's restricted. It
                            // usually will be.
                            nat_restricted: true,
                        });
                    }
                }
            }
        }

        WOk(MappedUdpSocket {
            socket: socket,
            endpoints: endpoints,
        }, warnings)
    }

    /// Create a new `MappedUdpSocket`
    pub fn new(mc: &MappingContext)
            -> WResult<MappedUdpSocket, MappedUdpSocketMapWarning, MappedUdpSocketNewError>
    {
        // Sometimes we might bind a socket to a random port then find that we have an IGD gateway
        // that could give us an unrestricted external port but that it can't map the random port
        // number we got. Hence we might need to try several times with different port numbers.
        let mut attempt = 0;
        'attempt: loop {
            attempt += 1;
            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(socket) => socket,
                Err(e) => return WErr(MappedUdpSocketNewError::CreateSocket { err: e }),
            };
            let (socket, warnings) = match Self::map(socket, mc) {
                WOk(s, ws) => (s, ws),
                WErr(e) => return WErr(MappedUdpSocketNewError::MapSocket { err: e }),
            };
            if attempt < 3 {
                for warning in &warnings {
                    match *warning {
                        // If we bound to a port that the IGD gateway can't map, rebind and try again.
                        MappedUdpSocketMapWarning::GetExternalPort {
                            err: igd::AddAnyPortError::ExternalPortInUse,
                            ..
                        } => continue 'attempt,
                        _ => (),
                    }
                }
            }
            return WOk(socket, warnings);
        }
    }
}

