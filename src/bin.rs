#[macro_use]
extern crate log;
extern crate simplelog;
extern crate socket2;

use e1_20::*;
use lumen_nova::*;
use pretty_hex::*;

use simplelog::*;

// All of the multicast code is lifted from this repo: https://github.com/bluejekyll/multicast-example
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::time::Duration;

// this will be common for all our sockets
fn new_socket(addr: &SocketAddr) -> io::Result<Socket> {
    let domain = if addr.is_ipv4() {
        Domain::ipv4()
    } else {
        Domain::ipv6()
    };

    let socket = Socket::new(domain, Type::dgram(), Some(Protocol::udp()))?;

    // we're going to use read timeouts so that we don't hang waiting for packets
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;

    Ok(socket)
}

fn join_multicast(addr: SocketAddr) -> io::Result<Socket> {
    let ip_addr = addr.ip();

    let socket = new_socket(&addr)?;

    // depending on the IP protocol we have slightly different work
    match ip_addr {
        IpAddr::V4(ref mdns_v4) => {
            // join to the multicast address, with all interfaces // 10.101.100.131
            socket.join_multicast_v4(mdns_v4, &Ipv4Addr::new(10, 101, 100, 131))?;
        }
        IpAddr::V6(ref mdns_v6) => {
            // join to the multicast address, with all interfaces (ipv6 uses indexes not addresses)
            socket.join_multicast_v6(mdns_v6, 0)?;
            socket.set_only_v6(true)?;
        }
    };

    // bind us to the socket address.
    socket.bind(&SockAddr::from(addr))?;
    Ok(socket)
}

fn new_sender(addr: &SocketAddr) -> io::Result<UdpSocket> {
    let socket = new_socket(addr)?;

    if addr.is_ipv4() {
        socket.set_multicast_if_v4(&Ipv4Addr::new(10, 101, 100, 131))?;

        socket.bind(&SockAddr::from(SocketAddr::new(
            Ipv4Addr::new(10, 101, 100, 131).into(),
            60000,
        )))?;
    } else {
        // *WARNING* THIS IS SPECIFIC TO THE AUTHORS COMPUTER
        //   find the index of your IPv6 interface you'd like to test with.
        socket.set_multicast_if_v6(5)?;

        socket.bind(&SockAddr::from(SocketAddr::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(),
            60000,
        )))?;
    }

    // convert to standard sockets...
    Ok(socket.into_udp_socket())
}

/// So we have to do some stupid things in this function
/// Specifically, the e1_20 library just wants data back and forth
/// But lumen_nova needs different packets if we're doing discovery or plain rdm
/// Additionally DISC_UNIQUE_BRANCH responses are partially parsed by the radio
/// So we have to do some parsing of the data... it's dumb.
fn lumen_nova_transport(data: &[u8]) -> Option<Vec<u8>> {

    let IPV4: IpAddr = Ipv4Addr::new(237, 200, 1, 1).into();
    // from port 60000 to port 60001
    let addr = SocketAddr::new(IPV4, 60000);
    let txaddr = SocketAddr::new(IPV4, 60001);
    
    let listener = join_multicast(addr).expect("failed to create listener");

    // let responder = new_socket(&addr)
    //                         .expect("failed to create responder")
    //                         .into_udp_socket();

    let responder = new_sender(&addr).expect("could not create sender!");

    let packet = e1_20::Pkt::deserialize(data.to_vec()).unwrap();

    if packet.pid == e1_20::DISC_UNIQUE_BRANCH {
        // Send a packet, get the response, parse it to see what it was.
        let inner = LNRdmDisc {
            command : 0x4407,
            uid_thing : [0x7c, 0xf2, 0x0b, 0x00, 0x55, 0x4c],
            rdm_packet : data.to_vec()
        };

        let inner_vec = inner.serialize();

        let outer = LNPkt {
            dst: [0x00, 0x1a, 0xf1, 0x02, 0x09, 0xee], 
            src: [0;6], 
            seq: data[15], 
            is_response: 0, 
            length: (inner_vec.len() + 1).try_into().unwrap(), 
            command: 0x03, 
            data: inner_vec
        };

        let outer_vec = outer.serialize();

        // println!("{:?}",outer_vec.hex_dump());

        responder
            .send_to(outer_vec.as_slice(), &txaddr)
            .expect("failed to respond");

        let mut buf = [0u8; 600]; // receive buffer

        loop {
            match listener.recv_from(&mut buf) {
                Ok((len, remote_addr)) => {
                    let data = &buf[..len];

                    // debug!("{:?}",data.hex_dump());
                    debug!("Got data");

                    let ln_pkt = LNPkt::deserialize(&data.to_vec()).unwrap();

                    if ln_pkt.command == 0x64 {
                        debug!("Got a discovery response");
                        let resp = LNRdmDiscResp::deserialize(&ln_pkt.data.to_vec()).unwrap();
                        if resp.cmd == 0x07 && resp.data_found == 0 {
                            debug!("None found");
                            return None;
                        } else if resp.cmd == 0x07 && resp.data_found == 1 {
                            debug!("Something found, but not one");
                            return Some(buf.to_vec()); // send some BS data back for it to choke on
                        } else if resp.cmd == 0x07 && resp.data_found == 0xff {
                            debug!("Single UID found: {:?}",resp.uid_found);
                            // Here's the fun part.  If we got a uid back, we now need to format that as a DISC_UNIQUE_BRANCH UID
                            let mut buffer : [u8; 24] = [0xFE; 24];
                            buffer[7] = 0xAA;
            
                            buffer[8] = resp.uid_found[0] | 0xAA;
                            buffer[9] = resp.uid_found[0] | 0x55;

                            buffer[10] = resp.uid_found[1] | 0xAA;
                            buffer[11] = resp.uid_found[1] | 0x55;

                            buffer[12] = resp.uid_found[2] | 0xAA;
                            buffer[13] = resp.uid_found[2] | 0x55;

                            buffer[14] = resp.uid_found[3] | 0xAA;
                            buffer[15] = resp.uid_found[3] | 0x55;

                            buffer[16] = resp.uid_found[4] | 0xAA;
                            buffer[17] = resp.uid_found[4] | 0x55;

                            buffer[18] = resp.uid_found[5] | 0xAA;
                            buffer[19] = resp.uid_found[5] | 0x55;

                            let mut crc : u16 = 0;

                            for byte in &buffer[8..20] {
                                crc = crc.overflowing_add(*byte as u16).0;
                            }

                            let crc_buffer = crc.to_be_bytes();

                            buffer[20] = crc_buffer[0] | 0xAA;
                            buffer[21] = crc_buffer[0] | 0x55;

                            buffer[22] = crc_buffer[1] | 0xAA;
                            buffer[23] = crc_buffer[1] | 0x55;

                            return Some(buffer.to_vec());
                        }
                    }


                    

                }
                Err(err) => {
                    error!("server: got an error: {}", err);
                    return None;
                }
            }

        }

        return None;


    }

    else {
        // send a regular RDM packet
        let inner = LNRdmNormal {
            command : 0x52,
            uid_thing : [0x7c, 0xf2, 0x0b, 0x00, 0x55, 0x4c],
            rdm_packet : data.to_vec()
        };

        let inner_vec = inner.serialize();

        let outer = LNPkt {
            dst: [0x00, 0x1a, 0xf1, 0x02, 0x09, 0xee], 
            src: [0;6], 
            seq: data[15], // does it care about sequence?
            is_response: 0, 
            length: (inner_vec.len() + 1).try_into().unwrap(), 
            command: 0x03, 
            data: inner_vec
        };

        let outer_vec = outer.serialize();

        // println!("{:?}",outer_vec.hex_dump());

        responder
        .send_to(outer_vec.as_slice(), &txaddr)
        .expect("failed to respond");

    let mut buf = [0u8; 600]; // receive buffer

    loop {
        match listener.recv_from(&mut buf) {
            Ok((len, remote_addr)) => {
                let data = &buf[..len];

                // debug!("{:?}",data.hex_dump());
                // debug!("Got data");

                let ln_pkt = LNPkt::deserialize(&data.to_vec()).unwrap();

                if ln_pkt.command == 0x72 {
                    debug!("Got an RDM response {}", (ln_pkt.length-1));
                    // let resp = Pkt::deserialize(ln_pkt.data.to_vec()).unwrap();
                    return Some(ln_pkt.data[..(ln_pkt.length-1) as usize].to_vec());
                }


                

            }
            Err(err) => {
                error!("server: got an error: {}", err);
                return None;
            }
        }

    }

    return None;

    }



    return None;
}

fn main() {
    // Statements here are executed when the compiled binary is called

    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Debug,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ), // Filter to debug, output to termial
    ])
    .unwrap();

    // Print text to the console
    debug!("Hello World!");

    // 4c55:000bf280
    let my_uid = Uid::new(0x4c55,0x000bf280);

    debug!("{:?}", do_discovery_algo(lumen_nova_transport,&my_uid));

}