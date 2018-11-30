use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

pub const NAME: &str = "rip";
pub const VERSION: &str = "0.1.0";
pub const ABOUT: &str = "Rip is a simple client/server to retrieving a public IP via UDP.";
pub const AUTHOR: &str = "Kevin Cotugno <kevin@kevincotugno.com>";

pub const DEFAULT_PORT: u16 = 44353;

const MAPPED_IPV4_KEY: u16 = 0xFFFF;

pub fn run_client(dest: SocketAddr) -> Result<IpAddr, String> {
    let socket = match open_socket(dest.is_ipv6(), 0) {
        Ok(v) => v,
        Err(err) => return Err(format!("{}", err)),
    };

    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    do_request(dest, &socket)
}

pub fn run_server(port: u16) -> Result<(), String> {
    let socket = match open_socket(true, port) {
        Ok(v) => v,
        Err(err) => return Err(format!("{}", err)),
    };
    eprintln!("Listening on: {:?}", socket);

    let mut unused = [0; 1024];
    loop {
        let (_, src) = match socket.recv_from(&mut unused) {
            Ok(v) => v,
            Err(err) => return Err(format!("Failed to read message: {}", err)),
        };
        eprintln!("Request from: {}", format!("{}", src.ip()));

        let (msg, size) = build_msg(src.ip());
        let res = socket.send_to(&msg[..size], src);
        if res.is_err() {
            eprintln!(
                "error sending response to {}, with err: ",
                res.err().unwrap()
            );
        }
    }
}

pub fn parse_socket_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    match parse_ip(host) {
        Ok(ip) => Ok(SocketAddr::new(ip, port)),
        Err(v) => Err(v),
    }
}

fn open_socket(ipv6: bool, port: u16) -> io::Result<UdpSocket> {
    UdpSocket::bind(if ipv6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    })
}

fn parse_ip(host: &str) -> Result<IpAddr, String> {
    match host.parse() {
        Ok(ip) => Ok(ip),
        Err(err) => Err(format!(
            "Unable to parse host: {}, with error: {}",
            host, err
        )),
    }
}

fn do_request(dest: SocketAddr, socket: &UdpSocket) -> Result<IpAddr, String> {
    if socket.connect(dest).is_err() {
        return Err(format!(
            "Unable to connect: {}",
            socket.take_error().unwrap().unwrap()
        ));
    }

    if socket.send(&[]).is_err() {
        return Err(format!(
            "Failed to send request: {}",
            socket.take_error().unwrap().unwrap()
        ));
    }

    let mut buf = [0; 1024];
    let count = match socket.recv(&mut buf) {
        Ok(size) => size,
        Err(error) => return Err(format!("Error reading response: {}", error)),
    };

    parse_raw_msg(&buf[..count])
}

fn parse_raw_msg(data: &[u8]) -> Result<IpAddr, String> {
    if data.is_empty() {
        return Err(String::from("empty message"));
    }

    match data[0] {
        4 => {
            if data.len() > 4 {
                Ok(IpAddr::V4(Ipv4Addr::new(
                    data[1], data[2], data[3], data[4],
                )))
            } else {
                println!("{}", data.len());
                Err(String::from("wrong number of octets for IPv4 address"))
            }
        }
        6 => {
            if data.len() > 16 {
                Ok(IpAddr::V6(Ipv6Addr::new(
                    rebuild_seg(data[1], data[2]),
                    rebuild_seg(data[3], data[4]),
                    rebuild_seg(data[5], data[6]),
                    rebuild_seg(data[7], data[8]),
                    rebuild_seg(data[9], data[10]),
                    rebuild_seg(data[11], data[12]),
                    rebuild_seg(data[13], data[14]),
                    rebuild_seg(data[15], data[16]),
                )))
            } else {
                Err(String::from("wrong number of segments for IPv6 address"))
            }
        }
        _ => Err(String::from("invalid IP type")),
    }
}

fn rebuild_seg(i: u8, j: u8) -> u16 {
    let mut x: u16 = u16::from(i);
    x <<= 8;
    x |= u16::from(j);
    x
}

fn build_msg(ip: IpAddr) -> ([u8; 17], usize) {
    let mut msg = [0; 17];

    let populate = |octets: &[u8], dest: &mut [u8]| {
        if octets.len() == 4 {
            dest[0] = 4;
        } else {
            dest[0] = 6;
        }

        for (i, oct) in octets.iter().enumerate() {
            dest[i + 1] = *oct;
        }
    };

    let size = match ip {
        IpAddr::V4(v4) => {
            populate(&v4.octets()[..], &mut msg);
            5
        }
        IpAddr::V6(v6) => {
            let v4 = v6.to_ipv4();

            if v4.is_some() && v6.segments()[5] == MAPPED_IPV4_KEY {
                populate(&v4.unwrap().octets()[..], &mut msg);
                5
            } else {
                populate(&v6.octets()[..], &mut msg);
                17
            }
        }
    };

    (msg, size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_ipv4() -> Result<(), String> {
        match parse_ip("1.2.3.4") {
            Ok(v) => ipv4_with_octets(v, 1, 2, 3, 4),
            Err(error) => Err(String::from(format!("Should be ok, {}", error))),
        }
    }

    #[test]
    fn parses_valid_ipv6() -> Result<(), String> {
        match parse_ip("2423:33:dfe3::1") {
            Ok(v) => ipv6_with_segments(v, 0x2423, 0x33, 0xdfe3, 0, 0, 0, 0, 1),
            Err(error) => Err(String::from(format!("Should be ok, {}", error))),
        }
    }

    #[test]
    fn errors_invalid_ips() -> Result<(), String> {
        let host = "2423:33:dfe3:invalid::1";
        match parse_ip(host) {
            Ok(v) => Err(String::from(format!("Should have returned error, {}", v))),
            Err(err) => {
                let expected = format!(
                    "Unable to parse host: {}, with error: invalid IP address syntax",
                    host
                );
                if err != expected {
                    Err(String::from(expected))
                } else {
                    Ok(())
                }
            }
        }
    }

    fn ipv4_with_octets(ip: IpAddr, a: u8, b: u8, c: u8, d: u8) -> Result<(), String> {
        match ip {
            IpAddr::V4(addr) => {
                if addr.octets() == [a, b, c, d] {
                    Ok(())
                } else {
                    Err(String::from(format!("octets do not match: {}", addr)))
                }
            }
            IpAddr::V6(_) => Err(String::from("is a ipv6 address")),
        }
    }

    fn ipv6_with_segments(
        ip: IpAddr,
        a: u16,
        b: u16,
        c: u16,
        d: u16,
        e: u16,
        f: u16,
        g: u16,
        h: u16,
    ) -> Result<(), String> {
        match ip {
            IpAddr::V4(_) => Err(String::from("is a ipv4 address")),
            IpAddr::V6(addr) => {
                if addr.segments() == [a, b, c, d, e, f, g, h] {
                    Ok(())
                } else {
                    Err(String::from(format!("segments do not match: {}", addr)))
                }
            }
        }
    }
}
