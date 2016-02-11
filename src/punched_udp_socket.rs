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
use std;
use std::thread;

use cbor;
use time;
use socket_addr::SocketAddr;
use w_result::{WResult, WOk, WErr};

use rendezvous_info::{PrivRendezvousInfo, PubRendezvousInfo};
use rendezvous_info;
use socket_utils::RecvUntil;

#[derive(Debug, RustcEncodable, RustcDecodable)]
struct HolePunch {
    pub secret: [u8; 4],
    pub ack: bool,
}

/// Used for reporting warnings inside `UdpPunchHoleWarning`
#[derive(Debug)]
pub struct HolePunchPacketData {
    data: HolePunch,
}

/// A udp socket that has been hole punched.
pub struct PunchedUdpSocket {
    /// The UDP socket.
    pub socket: UdpSocket,
    /// The remote address that this socket is able to send messages to and receive messages from.
    pub peer_addr: SocketAddr,
}

quick_error! {
    /// Warnings raise by `PunchedUdpSocket::punch_hole`
    #[derive(Debug)]
    #[allow(variant_size_differences)]
    pub enum UdpPunchHoleWarning {
        /// Received a hole punch packet that does correspond to the connection we are trying to
        /// make. Possibly, hole punch packets from an unrelated connection or arriving on this socket.
        UnexpectedHolePunchPacket {
            hole_punch: HolePunchPacketData,
        } {
            description("Received a hole punch packet that does correspond to the \
                         connection we are trying to make. Possibly, hole punch packets \
                         from an unrelated connection or arriving on this socket.")
            display("Received a hole punch packet that does correspond to the \
                     connection we are trying to make. Possibly, hole punch packets \
                     from an unrelated connection or arriving on this socket. Debug \
                     info: {:#?}", hole_punch)
        }
        /// Received invalid data on the udp socket while hole punching.
        InvalidHolePunchPacket {
            err: cbor::CborError,
        } {
            description("Received invalid data on the udp socket while hole punching")
            display("Received invalid data on the udp socket while hole punching. \
                     cbor decoding produced the error: {}", err)
            cause(err)
        }
    }
}

quick_error! {
    /// Error returned by PunchedUdpSocket::punch_hole
    #[derive(Debug)]
    pub enum UdpPunchHoleError {
        /// Timed out waiting for a response from the peer.
        TimedOut {
            description("Timed out waiting for a response from the peer.")
        }
        /// IO error when using socket
        Io {
            err: io::Error,
        } {
            description("IO error when using socket")
            display("IO error when using socket: {}", err)
            cause(err)
        }
    }
}

impl From<UdpPunchHoleError> for io::Error {
    fn from(err: UdpPunchHoleError) -> io::Error {
        match err {
            UdpPunchHoleError::TimedOut => io::Error::new(io::ErrorKind::TimedOut,
                                                          "Udp hole punching timed out \
                                                           waiting for a response from \
                                                           the peer"),
            UdpPunchHoleError::Io { err } => err,
        }
    }
}

impl PunchedUdpSocket {
    /// Punch a udp socket using a mapped socket and the peer's rendezvous info.
    pub fn punch_hole(socket: UdpSocket,
                      our_priv_rendezvous_info: PrivRendezvousInfo,
                      their_pub_rendezvous_info: PubRendezvousInfo)
        -> WResult<PunchedUdpSocket, UdpPunchHoleWarning, UdpPunchHoleError>
    {
        let mut warnings = Vec::new();

        let (endpoints, their_secret)
            = rendezvous_info::decompose(their_pub_rendezvous_info);
        let our_secret
            = rendezvous_info::get_priv_secret(our_priv_rendezvous_info);

        // Cbor seems to serialize into bytes of different sizes and
        // it sometimes exceeded 16 bytes, let's be safe and use 128.
        const MAX_DATAGRAM_SIZE: usize = 128;

        let send_data = {
            let hole_punch = HolePunch {
                secret: our_secret,
                ack: false,
            };
            let mut enc = ::cbor::Encoder::from_memory();
            enc.encode(::std::iter::once(&hole_punch)).unwrap();
            enc.into_bytes()
        };

        assert!(send_data.len() <= MAX_DATAGRAM_SIZE,
                format!("Data exceed MAX_DATAGRAM_SIZE in blocking_udp_punch_hole: {} > {}",
                        send_data.len(),
                        MAX_DATAGRAM_SIZE));

        let mut recv_data = [0u8; MAX_DATAGRAM_SIZE];

        // TODO(canndrew): Have a hard think about whether this is the best possible algorithm for
        // doing this.
        //
        // As far as I can see, the desired properties are:
        //  (a) We shouldn't read from the socket if the peer might have already returned their
        //      socket to the caller and started sending us real data. Otherwise we have to either.
        //      drop that data or return it in the PunchedUdpSocket struct.
        //  (b) We should only return the socket once there are no more hole-punch messages to
        //      receive. Otherwise the caller will start reading from the socket and find crap on the wire.
        //  (c) We should try to return as soon as possible after establishing a connection.
        //  (d) We should account for the fact that UDP is unreliable by resending messages.
        //
        // The problem is none of these requirements are possible to fulfill 100% of the time and
        // they all conflict with each other. So we need to decide how bad these problems are
        // relative to each other. In the case of (a) sending back data inside PunchedUdpSocket
        // wouldn't be the end of the world but it would be pretty annoying for the user as they'd
        // need to process that data and couldn't just start using their socket whereever it's
        // needed. Applications that use UDP should account for the fact that data can dissapear
        // anyway but it might be problematic for some apps if the very first chunk of data very
        // often dissapears. In the case of (b) applications need to account for the fact that
        // random data can sometimes appear on a UDP socket but they're probably not expecting to
        // get random data from the peer they're talking to. We should at the very least make sure
        // our hole punch packets are easily recognizable and give the user a facility to identify
        // them and throw them away. (c) is important but it conflicts with (b) and (d). In the
        // case of (d) it would helpful to have some idea of the probability of a given packet
        // being lost and balance that against (c).
        //
        // Assuming we successfully punch a hole there's four ways this can happen: (0) we get one
        // of their hole punching messages and it's from an address we were sending to. In this
        // case they likely got our hole punch message(s) aswell although it's possible the packet
        // got dropped. (1) We get one of their hole punching messages from an address that we
        // weren't sending to. In this case they haven't received any of our messages and we'll
        // definitely need to send an ack to their address. (2) We receive an ack to one of our
        // messages and it's from an address we weren't sending to. I don't think this should ever
        // happen. (3) We receive an ack to one of our packets and it's from an address we were
        // sending to. In this case they likely initially didn't have an address they could contact
        // us on.
        //
        // For now we keep the algorithm simple: If we get a hole punch message we send back two
        // acks with a delay in between before returning. If we get an ack we return immediately.

        // Spend TOTAL_TIMEOUT_MS trying to get their actual address that we can
        // communicate with.

        const DELAY_BETWEEN_RESENDS_MS: i64 = 600;
        const TOTAL_TIMEOUT_MS: i64 = 10000;

        let start_time = time::SteadyTime::now();
        let mut deadline = start_time;
        let total_deadline = start_time + time::Duration::milliseconds(TOTAL_TIMEOUT_MS);
        while deadline < total_deadline {
            deadline = deadline + time::Duration::milliseconds(DELAY_BETWEEN_RESENDS_MS);
            for endpoint in &endpoints {
                let addr = &endpoint.addr;
                // TODO(canndrew): How should we handle partial write?
                let _ = match socket.send_to(&send_data[..], &**addr) {
                    Ok(n) => n,
                    Err(e) => return WErr(UdpPunchHoleError::Io { err: e }),
                };
            }
            // Keep reading until it's time to send to all endpoints again.
            loop {
                let (read_size, addr) = match socket.recv_until(&mut recv_data[..], deadline) {
                    Ok(Some(x)) => x,
                    Ok(None) => break,
                    Err(e) => return WErr(UdpPunchHoleError::Io { err: e }),
                };
                match ::cbor::Decoder::from_reader(&recv_data[..read_size])
                             .decode::<HolePunch>()
                             .next() {
                    Some(Ok(hp)) => {
                        if hp.secret == our_secret && hp.ack {
                            return WOk(PunchedUdpSocket {
                                socket: socket,
                                peer_addr: addr,
                            }, warnings);
                        }
                        if hp.secret == their_secret {
                            let send_data = {
                                let hole_punch = HolePunch {
                                    secret: their_secret,
                                    ack: true,
                                };
                                let mut enc = ::cbor::Encoder::from_memory();
                                enc.encode(::std::iter::once(&hole_punch)).unwrap();
                                enc.into_bytes()
                            };

                            assert!(send_data.len() <= MAX_DATAGRAM_SIZE,
                                    format!("Data exceed MAX_DATAGRAM_SIZE in blocking_udp_punch_hole: {} > {}",
                                            send_data.len(),
                                            MAX_DATAGRAM_SIZE));

                            // TODO(canndrew): handle partial writes.
                            let _ = match socket.send_to(&send_data[..], &*addr) {
                                Ok(n) => n,
                                Err(e) => return WErr(UdpPunchHoleError::Io { err: e }),
                            };
                            thread::sleep(std::time::Duration::from_millis(100));
                            let _ = match socket.send_to(&send_data[..], &*addr) {
                                Ok(n) => n,
                                Err(e) => return WErr(UdpPunchHoleError::Io { err: e }),
                            };
                            return WOk(PunchedUdpSocket {
                                socket: socket,
                                peer_addr: addr,
                            }, warnings);
                        }
                        // Protect against a malicious peer sending us loads of spurious data.
                        if warnings.len() < 10 {
                            warnings.push(UdpPunchHoleWarning::UnexpectedHolePunchPacket {
                                hole_punch: HolePunchPacketData {
                                    data: hp,
                                },
                            });
                        }
                    }
                    Some(Err(e)) => {
                        // Protect against a malicious peer sending us loads of spurious data.
                        if warnings.len() < 10 {
                            warnings.push(UdpPunchHoleWarning::InvalidHolePunchPacket {
                                err: e,
                            });
                        }
                    }
                    None => (),
                };
            }
        }
        WErr(UdpPunchHoleError::TimedOut)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use rand;

    use mapping_context::MappingContext;
    use mapped_udp_socket::MappedUdpSocket;
    use punched_udp_socket::PunchedUdpSocket;
    use rendezvous_info::gen_rendezvous_info;

    fn two_peers_punch_hole_over_loopback() {
        let mapping_context = unwrap_result!(MappingContext::new().result_discard());
        let mapped_socket_0 = unwrap_result!(MappedUdpSocket::new(&mapping_context).result_discard());
        let mapped_socket_1 = unwrap_result!(MappedUdpSocket::new(&mapping_context).result_discard());

        let socket_0 = mapped_socket_0.socket;
        let socket_1 = mapped_socket_1.socket;
        let (priv_info_0, pub_info_0) = gen_rendezvous_info(mapped_socket_0.endpoints);
        let (priv_info_1, pub_info_1) = gen_rendezvous_info(mapped_socket_1.endpoints);

        let (tx_0, rx_0) = mpsc::channel();
        let (tx_1, rx_1) = mpsc::channel();

        let jh_0 = thread!("two_peers_hole_punch_over_loopback punch socket 0", move || {
            let res = PunchedUdpSocket::punch_hole(socket_0,
                                                   priv_info_0,
                                                   pub_info_1);
            tx_0.send(res);
        });
        let jh_1 = thread!("two_peers_hole_punch_over_loopback punch socket 1", move || {
            let res = PunchedUdpSocket::punch_hole(socket_1,
                                                   priv_info_1,
                                                   pub_info_0);
            tx_1.send(res);
        });

        thread::sleep(Duration::from_millis(500));
        let punched_socket_0 = unwrap_result!(unwrap_result!(rx_0.try_recv()));
        let punched_socket_1 = unwrap_result!(unwrap_result!(rx_1.try_recv()));

        const DATA_LEN: usize = 8;
        let data_send: [u8; DATA_LEN] = rand::random();
        let mut data_recv;
        
        // Send data from 0 to 1
        data_recv = [0u8; DATA_LEN];
        punched_socket_0.socket.send_to(&data_send[..], &*punched_socket_0.peer_addr);
        let (n, _) = unwrap_result!(punched_socket_1.socket.recv_from(&mut data_recv[..]));
        assert_eq!(n, DATA_LEN);
        assert_eq!(data_send, data_recv);

        // Send data from 1 to 0
        data_recv = [0u8; DATA_LEN];
        punched_socket_1.socket.send_to(&data_send[..], &*punched_socket_1.peer_addr);
        let (n, _) = unwrap_result!(punched_socket_0.socket.recv_from(&mut data_recv[..]));
        assert_eq!(n, DATA_LEN);
        assert_eq!(data_send, data_recv);

        unwrap_result!(jh_0.join());
        unwrap_result!(jh_1.join());
    }
}

