// Copyright 2015 MaidSafe.net limited.
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

use std::io;
use std::net::{TcpStream, UdpSocket, Ipv4Addr, Ipv6Addr};
use std::net;
use socket_addr::SocketAddr;
use std::io::ErrorKind;
use net2;

/// A self interruptable receive trait that allows a timed-out period to be defined
pub trait RecvUntil {
    /// After specified timed-out period, the blocking receive method shall return with an error
    fn recv_until(&self,
                  buf: &mut [u8],
                  deadline: ::time::SteadyTime)
                  -> io::Result<Option<(usize, SocketAddr)>>;
}

impl RecvUntil for UdpSocket {
    fn recv_until(&self,
                  buf: &mut [u8],
                  deadline: ::time::SteadyTime)
                  -> io::Result<Option<(usize, SocketAddr)>> {
        let old_timeout = try!(self.read_timeout());
        loop {
            let current_time = ::time::SteadyTime::now();
            let timeout_ms = (deadline - current_time).num_milliseconds();

            if timeout_ms <= 0 {
                try!(self.set_read_timeout(old_timeout));
                return Ok(None);
            }

            // TODO (canndrew): should eventually be able to remove this conversion
            let timeout = ::std::time::Duration::from_millis(timeout_ms as u64);
            try!(self.set_read_timeout(Some(timeout)));

            match self.recv_from(buf) {
                Ok((bytes_len, addr)) => {
                    try!(self.set_read_timeout(old_timeout));
                    return Ok(Some((bytes_len, SocketAddr(addr))));
                },
                Err(e) => {
                    match e.kind() {
                        ErrorKind::TimedOut | ErrorKind::WouldBlock => {
                            try!(self.set_read_timeout(old_timeout));
                            return Ok(None);
                        },
                        ErrorKind::Interrupted => (),
                        // On Windows, when we send a packet to an endpoint
                        // which is not being listened on, the system responds
                        // with an ICMP packet "ICMP port unreachable".
                        // We do not care about this silly behavior, so we just
                        // ignore it.
                        // See here for more info:
                        // https://bobobobo.wordpress.com/2009/05/17/udp-an-existing-connection-was-forcibly-closed-by-the-remote-host/
                        ErrorKind::ConnectionReset => (),
                        _ => {
                            try!(self.set_read_timeout(old_timeout));
                            return Err(e);
                        },
                    }
                }
            }
        }
    }
}

// TODO(canndrew): Remove this once #[feature(ip)] is stable
pub fn ipv4_is_unspecified(addr: &Ipv4Addr) -> bool {
    addr.octets() == [0, 0, 0, 0]
}

// TODO(canndrew): Remove this once #[feature(ip)] is stable
pub fn ipv6_is_unspecified(addr: &Ipv6Addr) -> bool {
    addr.segments() == [0, 0, 0, 0, 0, 0, 0, 0]
}

#[cfg(target_family = "unix")]
pub fn enable_so_reuseport(sock: &net2::TcpBuilder) -> io::Result<()> {
    use net2::unix::UnixTcpBuilderExt;
    let _ = try!(sock.reuse_port(true));
    Ok(())
}

#[cfg(target_family = "windows")]
pub fn enable_so_reuseport(sock: &net2::TcpBuilder) -> io::Result<()> {
    Ok(())
}

// TODO(canndrew): This function should be deprecated once this issue
// (https://github.com/rust-lang-nursery/net2-rs/issues/26) is resolved.
#[cfg(target_family = "unix")]
#[allow(unsafe_code)]
pub fn tcp_builder_local_addr(sock: &net2::TcpBuilder) -> io::Result<net::SocketAddr> {
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
    let fd = sock.as_raw_fd();
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    let ret = stream.local_addr();
    let _ = stream.into_raw_fd();
    ret
}

#[cfg(target_family = "windows")]
#[allow(unsafe_code)]
pub fn tcp_builder_local_addr(sock: &net2::TcpBuilder) -> io::Result<net::SocketAddr> {
    use std::os::windows::io::{AsRawSocket, FromRawSocket};
    let fd = sock.as_raw_socket();
    let stream = unsafe { TcpStream::from_raw_socket(fd) };
    let ret = stream.local_addr();
    std::mem::forget(stream); // TODO(canndrew): Is this completely safe?
    ret
}

