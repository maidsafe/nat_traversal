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
use std::sync::mpsc;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use igd;
use net2;
use socket_addr::SocketAddr;
use w_result::{WResult, WErr, WOk};
use ip::{SocketAddrExt, IpAddr};
use maidsafe_utilities::serialisation::{deserialise, SerialisationError};
use time::SteadyTime;
use time;

use mapping_context::MappingContext;
use mapped_socket_addr::MappedSocketAddr;
use rendezvous_info::{PrivRendezvousInfo, PubRendezvousInfo};
use rendezvous_info;
use socket_utils;
use mapping_context;
use listener_message;
use utils;

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
        NewReusablyBoundSocket { err: NewReusablyBoundSocketError } {
            description("Error creating a reusably bound temporary socket for mapping.")
            display("Error creating a reusably bound temporary socket for mapping: {}", err)
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

quick_error! {
    /// Errors returned by new_reusably_bound_socket
    #[derive(Debug)]
    pub enum NewReusablyBoundSocketError {
        Create { err: io::Error } {
            description("Error creating socket.")
            display("Error creating socket: {}", err)
            cause(err)
        }
        EnableReuseAddr { err: io::Error } {
            description("Error setting SO_REUSEADDR on socket.")
            display("Error setting SO_REUSEADDR on socket. \
                     Got IO error: {}", err)
            cause(err)
        }
        EnableReusePort { err: io::Error } {
            description("Error setting SO_REUSEPORT on socket.")
            display("Error setting SO_REUSEPORT on socket. \
                     Got IO error: {}", err)
            cause(err)
        }
        Bind { err: io::Error } {
            description("Error binding new socket to the provided address. Likely a socket was \
                         already bound to this address without SO_REUSEPORT and SO_REUSEADDR \
                         being set")
            display("Error binding new socket to the provided address: {}. Likely a socket was \
                     already bound to this address without SO_REUSEPORT and SO_REUSEADDR being \
                     set", err)
            cause(err)
        }
    }
}

pub fn new_reusably_bound_socket(local_addr: &net::SocketAddr) -> Result<net2::TcpBuilder, NewReusablyBoundSocketError> {
    let socket_res = match SocketAddrExt::ip(local_addr) {
        IpAddr::V4(..) => net2::TcpBuilder::new_v4(),
        IpAddr::V6(..) => net2::TcpBuilder::new_v6(),
    };
    let socket = match socket_res {
        Ok(socket) => socket,
        Err(e) => return Err(NewReusablyBoundSocketError::Create { err: e }),
    };
    match socket.reuse_address(true) {
        Ok(_) => (),
        Err(e) => return Err(NewReusablyBoundSocketError::EnableReuseAddr { err: e }),
    };
    match socket_utils::enable_so_reuseport(&socket) {
        Ok(()) => (),
        Err(e) => return Err(NewReusablyBoundSocketError::EnableReusePort { err: e }),
    };
    match socket.bind(local_addr) {
        Ok(..) => (),
        Err(e) => return Err(NewReusablyBoundSocketError::Bind { err: e }),
    };
    Ok(socket)
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
                let mapping_socket = match new_reusably_bound_socket(&local_addr) {
                    Ok(mapping_socket) => mapping_socket,
                    Err(e) => return Err(MappedTcpSocketMapWarning::NewReusablyBoundSocket { err: e }),
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

quick_error! {
    #[derive(Debug)]
    pub enum TcpPunchHoleWarning {
        Connect { peer_addr: SocketAddr, err: io::Error } {
            description("Connecting to endpoint failed.")
            display("Connecting to endpoint {} failed: {}", peer_addr, err)
            cause(err)
        }
        Accept { err: io::Error } {
            description("Error accepting an incoming connection.")
            display("Error accepting an incoming connection: {}", err)
            cause(err)
        }
        StreamSetTimeout { err: io::Error } {
            description("Error setting the timeout on a connected stream.")
            display("Error setting the timeout on a connected stream: {}", err)
            cause(err)
        }
        StreamIo { peer_addr: SocketAddr, err: io::Error } {
            description("IO error communicating with a connected host.")
            display("IO error communicating with connected host at {}: {}", peer_addr, err)
            cause(err)
        }
        InvalidResponse { peer_addr: SocketAddr, data: [u8; 4] } {
            description("A connected host provided an invalid response to the handshake.")
            display("The connected host at {} provided an invalid response to the handshake: {:?}", peer_addr, data)
        }
    }
}

struct DisplayWarnings<'a>(pub &'a Vec<TcpPunchHoleWarning>);

impl<'a> fmt::Display for DisplayWarnings<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let DisplayWarnings(v) = *self;
        try!(write!(f, "[ "));
        for warning in v {
            try!(write!(f, "{} ", warning));
        }
        try!(write!(f, "]"));
        Ok(())
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum TcpPunchHoleError {
        SocketLocalAddr { err: io::Error } {
            description("Error getting the local address of the provided socket.")
            display("Error getting the local address of the provided socket: {}", err)
            cause(err)
        }
        NewReusablyBoundSocket { err: NewReusablyBoundSocketError } {
            description("Error binding another socket to the same local address as the provided socket.")
            display("Error binding another socket to the same local address as the provided socket: {}", err)
            cause(err)
        }
        Listen { err: io::Error } {
            description("Error listening on the provided socket.")
            display("Error listening on the provided socket: {}", err)
            cause(err)
        }
        TimedOut { warnings: Vec<TcpPunchHoleWarning> } {
            description("Tcp hole punching timed out without making a successful connection.")
            display("Tcp hole punching timed out without making a successful connection. The \
                     following warnings were raised during hole punching: {}", DisplayWarnings(warnings))
        }
    }
}

/// Perform a tcp rendezvous connect. `socket` should have been obtained from a
/// `MappedTcpSocket`.
pub fn tcp_punch_hole(socket: net2::TcpBuilder,
                      our_priv_rendezvous_info: PrivRendezvousInfo,
                      their_pub_rendezvous_info: PubRendezvousInfo)
                      -> WResult<TcpStream, TcpPunchHoleWarning, TcpPunchHoleError> {
    // In order to do tcp hole punching we connect to all of their endpoints in parallel while
    // simultaneously listening. All the sockets we use must be bound to the same local address. As
    // soon as we successfully connect and exchange secrets, or accept and exchange secrets, we
    // return.
    //
    // It would be way better to implement this using non-blocking sockets but at the moment mio
    // doesn't provide any way to convert a non-blocking socket back into a blocking socket. So
    // we're stuck with spawning (and then detaching) loads of threads. Setting the read/write
    // timeouts should prevent the detached threads from leaking indefinitely.

    // The total timeout for the entire function.
    let start_time = SteadyTime::now();
    let deadline = start_time + time::Duration::seconds(20);

    let mut warnings = Vec::new();

    let shutdown = Arc::new(AtomicBool::new(false));

    // The channel we will use to collect the results from the many worker threads.
    let (results_tx, results_rx) = mpsc::channel::<Option<Result<TcpStream, TcpPunchHoleWarning>>>();

    let our_secret = rendezvous_info::get_priv_secret(our_priv_rendezvous_info);
    let (their_endpoints, their_secret) = rendezvous_info::decompose(their_pub_rendezvous_info);

    let local_addr = match socket_utils::tcp_builder_local_addr(&socket) {
        Ok(local_addr) => local_addr,
        Err(e) => return WErr(TcpPunchHoleError::SocketLocalAddr { err: e }),
    };

    // Try connecting to every potential endpoint in a seperate thread.
    for endpoint in their_endpoints {
        let addr = endpoint.addr;
        // Important to call new_reusably_bound_socket outside the inner thread so that it's called
        // before the listen() call below.
        let mapping_socket = match new_reusably_bound_socket(&local_addr) {
            Ok(mapping_socket) => mapping_socket,
            Err(e) => return WErr(TcpPunchHoleError::NewReusablyBoundSocket { err: e }),
        };
        let results_tx_clone = results_tx.clone();
        let shutdown_clone = shutdown.clone();
        let _ = thread!("tcp_punch_hole connect", move || {
            let f = |timeout| {
                let mut stream = match mapping_socket.connect(&*addr) {
                    Ok(stream) => stream,
                    Err(e) => return Err(TcpPunchHoleWarning::Connect {
                        peer_addr: addr,
                        err: e,
                    }),
                };
                match stream.set_write_timeout(Some(timeout)) {
                    Ok(()) => (),
                    Err(e) => return Err(TcpPunchHoleWarning::StreamSetTimeout { err: e }),
                };
                match stream.set_read_timeout(Some(timeout)) {
                    Ok(()) => (),
                    Err(e) => return Err(TcpPunchHoleWarning::StreamSetTimeout { err: e }),
                };
                match stream.write_all(&our_secret[..]) {
                    Ok(()) => (),
                    Err(e) => return Err(TcpPunchHoleWarning::StreamIo {
                        peer_addr: addr,
                        err: e,
                    }),
                };
                let mut recv_data = [0u8; 4];
                match stream.read_exact(&mut recv_data[..]) {
                    Ok(()) => (),
                    Err(e) => return Err(TcpPunchHoleWarning::StreamIo {
                        peer_addr: addr,
                        err: e,
                    }),
                };
                if recv_data != their_secret {
                    return Err(TcpPunchHoleWarning::InvalidResponse {
                        peer_addr: addr,
                        data: recv_data,
                    });
                };
                match stream.set_write_timeout(None) {
                    Ok(()) => (),
                    Err(e) => return Err(TcpPunchHoleWarning::StreamSetTimeout { err: e }),
                };
                match stream.set_read_timeout(None) {
                    Ok(()) => (),
                    Err(e) => return Err(TcpPunchHoleWarning::StreamSetTimeout { err: e }),
                };
                Ok(stream)
            };
            loop {
                let now = SteadyTime::now();
                if now >= deadline || shutdown_clone.load(Ordering::SeqCst) {
                    break;
                }
                else {
                    let timeout = deadline - now;
                    let timeout = utils::time_duration_to_std_duration(timeout);
                    match f(timeout) {
                        Ok(stream) => {
                            let _ = results_tx_clone.send(Some(Ok(stream)));
                            break;
                        },
                        Err(e) => {
                            let _ = results_tx_clone.send(Some(Err(e)));
                            // So we don't continuously hammer an address we can't connect to.
                            thread::sleep(Duration::from_secs(1));
                            continue;
                        },
                    }
                }
            }
        });
    };

    // Listen for incoming connections.
    let listener = match socket.listen(128) {
        Ok(listener) => listener,
        Err(e) => return WErr(TcpPunchHoleError::Listen { err: e }),
    };
    let results_tx_clone = results_tx.clone();
    let shutdown_clone = shutdown.clone();
    let _ = thread!("tcp_punch_hole listen", move || {
        loop {
            let res = listener.accept();
            // First, check if we should shutdown.
            if shutdown_clone.load(Ordering::SeqCst) {
                break;
            };
            let (mut stream, addr) = match res {
                Ok(x) => x,
                Err(e) => {
                    match results_tx_clone.send(Some(Err(TcpPunchHoleWarning::Accept { err: e }))) {
                        Ok(()) => (),
                        Err(_) => break,
                    }
                    continue;
                },
            };

            // Spawn a new thread here to prevent someone from connecting then not sending any data
            // and preventing us from accepting any more connections.
            let results_tx_clone = results_tx_clone.clone();
            let now = SteadyTime::now();
            if now >= deadline {
                break;
            };
            let _ = thread!("tcp_punch_hole listen handshake", move || {
                let timeout = deadline - now;
                let timeout = utils::time_duration_to_std_duration(timeout);
                match stream.set_write_timeout(Some(timeout)) {
                    Ok(()) => (),
                    Err(e) => {
                        let _ = results_tx_clone.send(Some(Err(TcpPunchHoleWarning::StreamSetTimeout { err: e })));
                        return;
                    },
                };
                match stream.set_read_timeout(Some(timeout)) {
                    Ok(()) => (),
                    Err(e) => {
                        let _ = results_tx_clone.send(Some(Err(TcpPunchHoleWarning::StreamSetTimeout { err: e })));
                        return;
                    },
                };
                match stream.write_all(&our_secret[..]) {
                    Ok(()) => (),
                    Err(e) => {
                        let _ = results_tx_clone.send(Some(Err(TcpPunchHoleWarning::StreamIo {
                            peer_addr: SocketAddr(addr),
                            err: e,
                        })));
                        return;
                    },
                };
                let mut recv_data = [0u8; 4];
                match stream.read_exact(&mut recv_data[..]) {
                    Ok(()) => (),
                    Err(e) => {
                        let _ = results_tx_clone.send(Some(Err(TcpPunchHoleWarning::StreamIo {
                            peer_addr: SocketAddr(addr),
                            err: e,
                        })));
                        return;
                    },
                };
                if recv_data != their_secret {
                    let _ = results_tx_clone.send(Some(Err(TcpPunchHoleWarning::InvalidResponse {
                        peer_addr: SocketAddr(addr),
                        data: recv_data,
                    })));
                    return;
                }
                match stream.set_write_timeout(None) {
                    Ok(()) => (),
                    Err(e) => {
                        let _ = results_tx_clone.send(Some(Err(TcpPunchHoleWarning::StreamSetTimeout { err: e })));
                        return;
                    },
                };
                match stream.set_read_timeout(None) {
                    Ok(()) => (),
                    Err(e) => {
                        let _ = results_tx_clone.send(Some(Err(TcpPunchHoleWarning::StreamSetTimeout { err: e })));
                        return;
                    },
                };
                let _ = results_tx_clone.send(Some(Ok(stream)));
            });
        }
    });
    
    // Create a separate thread for timing out.
    // TODO(canndrew): We won't need to do this one this is fixed: https://github.com/rust-lang/rfcs/issues/962
    let results_tx_clone = results_tx.clone();
    let timeout_thread = thread!("tcp_punch_hole timeout", move || {
        let now = SteadyTime::now();
        let timeout = deadline - now;
        let timeout = utils::time_duration_to_std_duration(timeout);
        thread::park_timeout(timeout);
        let _ = results_tx_clone.send(None);
    });
    let timeout_thread_handle = timeout_thread.thread();

    // Process the results that the worker threads send us.
    loop {
        match results_rx.recv() {
            // We timed out.
            Ok(None) => {
                timeout_thread_handle.unpark();
                shutdown.store(true, Ordering::SeqCst);
                let _ = TcpStream::connect(local_addr);
                return WErr(TcpPunchHoleError::TimedOut { warnings: warnings });
            },

            // Success!
            Ok(Some(Ok(stream))) => {
                timeout_thread_handle.unpark();
                shutdown.store(true, Ordering::SeqCst);
                let _ = TcpStream::connect(local_addr);
                return WOk(stream, warnings);
            },
            
            // One of the working threads raised a warning.
            Ok(Some(Err(e))) => {
                warnings.push(e);
            },

            // All the senders have closed. This could only happen if all of the worker threads
            // panicked.
            Err(_) => panic!("In tcp_punch_hole results_rx.recv() returned Err"),
        }
    }
}

