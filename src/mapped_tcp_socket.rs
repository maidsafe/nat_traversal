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

use std::net;
use std::net::TcpStream;
use std::io;
use std::io::{Read, Write};
use std::time::Duration;
use std::thread;
use std::str;

use igd;
use net2;
use socket_addr::SocketAddr;
use w_result::{WResult, WErr, WOk};
use ip::{SocketAddrExt, IpAddr};
use maidsafe_utilities::serialisation::{deserialise, SerialisationError};

use mapping_context::MappingContext;
use mapped_socket_addr::MappedSocketAddr;
use rendezvous_info::{PrivRendezvousInfo, PubRendezvousInfo};
use socket_utils;
use mapping_context;
use listener_message;

/// A tcp socket for which we know our external endpoints.
pub struct MappedTcpSocket {
    /// A bound, but neither listening or connected tcp socket. The socket is
    /// bound to be reuseable (ie. SO_REUSEADDR is set as is SO_REUSEPORT on
    /// unix).
    pub socket: net2::TcpBuilder,
    /// The known endpoints of this socket.
    pub endpoints: Vec<MappedSocketAddr>,
}

quick_error! {
    /// Errors returned by MappedTcpSocket::map
    #[derive(Debug)]
    pub enum MappedTcpSocketMapError {
        SocketLocalAddr { err: io::Error } {
            description("Error getting local address of socket \
                         (have you called bind() on the socket?)")
            display("Error getting local address of socket. \
                     TcpBuilder::local_addr returned an error: {} \
                     (have you called bind() on the socket?).",
                     err)
            cause(err)
        }
    }
}

quick_error! {
    /// Warnings raised by MappedTcpSocket::map
    #[derive(Debug)]
    pub enum MappedTcpSocketMapWarning {
        FindGateway {
            err: igd::SearchError
        } {
            description("Error searching for IGD gateway")
            display("Error searching for IGD gateway. \
                     igd::search_gateway_from_timeout returned an error: {}",
                     err)
            cause(err)
        }
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
        MappingSocketCreate { err: io::Error } {
            description("Error creating a temporary socket for mapping.")
            display("Error creating a temporary socket for mapping: {}", err)
            cause(err)
        }
        MappingSocketEnableReuseAddr { err: io::Error } {
            description("Error setting SO_REUSEADDR on a temporary socket created for mapping.")
            display("Error setting SO_REUSEADDR on a temporary socket created for mapping. \
                     Got IO error: {}", err)
            cause(err)
        }
        MappingSocketEnableReusePort { err: io::Error } {
            description("Error setting SO_REUSEPORT on a temporary socket created for mapping.")
            display("Error setting SO_REUSEPORT on a temporary socket created for mapping. \
                     Got IO error: {}", err)
            cause(err)
        }
        MappingSocketBind { err: io::Error } {
            description("Error binding a temporary socket created for mapping to the same address \
                         as the argument socket. Were SO_REUSEPORT and SO_REUSEADDR set on the \
                         argument socket before it was bound?")
            display("Error binding a temporary socket created for mapping to the same address as \
                     the argument socket. IO error: {}. Were SO_REUSEPORT and SO_REUSEADDR set on \
                     the argument socket before it was bound?", err)
            cause(err)
        }
        MappingSocketConnect {
            addr: SocketAddr,
            err: io::Error
        } {
            description("Error connecting to a mapping server.")
            display("Error connecting to mapping server at address {}. connect() returned an \
                     error: {}", addr, err)
            cause(err)
        }
        MappingSocketWrite { err: io::Error } {
            description("Error writing to temporary socket.")
            display("Error writing to temporary socket: {}", err)
            cause(err)
        }
        MappingSocketRead { err: io::Error } {
            description("Error reading from temporary socket.")
            display("Error reading from temporary socket: {}", err)
            cause(err)
        }
        Deserialise { addr: SocketAddr, err: SerialisationError, response: Vec<u8> } {
            description("Error deserialising a response from a mapping server. Are you sure \
                         you've connected to a mapping server?")
            display("Error deserialising a response from mapping server at address {}: {}. \
                     Response: \"{}\". Are you sure you've connected to a mapping server?",
                     addr, err, {
                         match str::from_utf8(response) {
                             Ok(r) => r,
                             Err(e) => "<Response contains binary data>",
                         }
                     }
            )
        }
    }
}

quick_error! {
    /// Errors returned by MappedTcpSocket::new
    #[derive(Debug)]
    pub enum MappedTcpSocketNewError {
        CreateSocket { err: io::Error } {
            description("Error creating TCP socket")
            display("Error creating TCP socket: {}", err)
            cause(err)
        }
        EnableReuseAddr { err: io::Error } {
            description("Error enabling SO_REUSEADDR on new socket")
            display("Error enabling SO_REUSEADDR on new socket: {}", err)
            cause(err)
        }
        EnableReusePort { err: io::Error } {
            description("Error enabling SO_REUSEPORT on new socket")
            display("Error enabling SO_REUSEPORT on new socket: {}", err)
            cause(err)
        }
        Bind { err: io::Error } {
            description("Error binding new socket")
            display("Error binding new socket: {}", err)
            cause(err)
        }
        Map { err: MappedTcpSocketMapError } {
            description("Error mapping new socket")
            display("Error mapping new socket: {}", err)
            cause(err)
        }
    }
}

impl MappedTcpSocket {
    /// Map an existing tcp socket. The socket must bound but not connected. It must have been
    /// bound with SO_REUSEADDR and SO_REUSEPORT options (or equivalent) set.
    pub fn map(socket: net2::TcpBuilder, mc: &MappingContext)
               -> WResult<MappedTcpSocket, MappedTcpSocketMapWarning, MappedTcpSocketMapError>
    {
        let mut endpoints = Vec::new();
        let mut warnings = Vec::new();

        let local_addr = match socket_utils::tcp_builder_local_addr(&socket) {
            Ok(local_addr) => local_addr,
            Err(e) => return WErr(MappedTcpSocketMapError::SocketLocalAddr { err: e }),
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
                            match gateway.get_any_address(igd::PortMappingProtocol::TCP,
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
                                    warnings.push(MappedTcpSocketMapWarning::GetExternalPort {
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
                                    warnings.push(MappedTcpSocketMapWarning::FindGateway {
                                        err: e
                                    });
                                    None
                                }
                            }
                        }
                    };
                    // If we have a gateway, ask it for an external address.
                    if let Some(gateway) = gateway_opt {
                        match gateway.get_any_address(igd::PortMappingProtocol::TCP,
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
                                warnings.push(MappedTcpSocketMapWarning::GetExternalPort {
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
        
        let mut mapping_threads = Vec::new();
        let simple_servers = mapping_context::simple_tcp_servers(&mc);
        for simple_server in simple_servers {
            mapping_threads.push(thread::spawn(move || {
                let mapping_socket_res = match SocketAddrExt::ip(&local_addr) {
                    IpAddr::V4(..) => net2::TcpBuilder::new_v4(),
                    IpAddr::V6(..) => net2::TcpBuilder::new_v6(),
                };
                let mapping_socket = match mapping_socket_res {
                    Ok(mapping_socket) => mapping_socket,
                    Err(e) => return Err(MappedTcpSocketMapWarning::MappingSocketCreate { err: e }),
                };
                match mapping_socket.reuse_address(true) {
                    Ok(_) => (),
                    Err(e) => return Err(MappedTcpSocketMapWarning::MappingSocketEnableReuseAddr { err: e }),
                };
                match socket_utils::enable_so_reuseport(&mapping_socket) {
                    Ok(()) => (),
                    Err(e) => return Err(MappedTcpSocketMapWarning::MappingSocketEnableReusePort { err: e }),
                };
                match mapping_socket.bind(local_addr) {
                    Ok(..) => (),
                    Err(e) => return Err(MappedTcpSocketMapWarning::MappingSocketBind { err: e }),
                };
                let mut stream = match mapping_socket.connect(&*simple_server) {
                    Ok(stream) => stream,
                    Err(e) => return Err(MappedTcpSocketMapWarning::MappingSocketConnect {
                        addr: simple_server,
                        err: e
                    }),
                };
                let send_data = listener_message::REQUEST_MAGIC_CONSTANT;
                // TODO(canndrew): What should we do if we get a partial write?
                let _ = match stream.write(&send_data[..]) {
                    Ok(n) => n,
                    Err(e) => return Err(MappedTcpSocketMapWarning::MappingSocketWrite { err: e }),
                };

                const MAX_DATAGRAM_SIZE: usize = 256;
                let mut recv_data = [0u8; MAX_DATAGRAM_SIZE];
                let n = match stream.read(&mut recv_data[..]) {
                    Ok(n) => n,
                    Err(e) => return Err(MappedTcpSocketMapWarning::MappingSocketRead { err: e }),
                };
                let listener_message::EchoExternalAddr { external_addr } = match deserialise::<listener_message::EchoExternalAddr>(&recv_data[..n]) {
                    Ok(msg) => msg,
                    Err(e) => return Err(MappedTcpSocketMapWarning::Deserialise {
                        addr: simple_server,
                        err: e,
                        response: recv_data[..n].to_vec(),
                    }),
                };
                Ok(external_addr)
            }));
        }
        for mapping_thread in mapping_threads {
            match unwrap_result!(mapping_thread.join()) {
                Ok(external_addr) => {
                    endpoints.push(MappedSocketAddr {
                        addr: external_addr,
                        nat_restricted: true,
                    });
                },
                Err(e) => {
                    warnings.push(e);
                },
            }
        }
        WOk(MappedTcpSocket {
            socket: socket,
            endpoints: endpoints,
        }, warnings)
    }

    /// Create a new `MappedTcpSocket`
    pub fn new(mc: &MappingContext) -> WResult<MappedTcpSocket, MappedTcpSocketMapWarning, MappedTcpSocketNewError> {
        let socket = match net2::TcpBuilder::new_v4() {
            Ok(socket) => socket,
            Err(e) => return WErr(MappedTcpSocketNewError::CreateSocket { err: e }),
        };
        match socket.reuse_address(true) {
            Ok(_) => (),
            Err(e) => return WErr(MappedTcpSocketNewError::EnableReuseAddr { err: e }),
        };
        match socket_utils::enable_so_reuseport(&socket) {
            Ok(()) => (),
            Err(e) => return WErr(MappedTcpSocketNewError::EnableReusePort { err: e }),
        };
        // need to connect to a bunch of guys in parallel and get our addresses.
        // need a bunch of sockets that are bound to the same local port.
        match socket.bind("0.0.0.0:0") {
            Ok(_)  => (),
            Err(e) => return WErr(MappedTcpSocketNewError::Bind { err: e }),
        };

        MappedTcpSocket::map(socket, mc).map_err(|e| MappedTcpSocketNewError::Map { err: e })
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
