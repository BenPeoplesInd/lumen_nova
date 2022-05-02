#[macro_use]
extern crate log;
extern crate simplelog;
extern crate socket2;

use hex;

use e1_20::*;
use lumen_nova::*;
use pretty_hex::*;

use simplelog::*;

use hyper::{
    header::CONTENT_TYPE,
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server,
};
use lazy_static::lazy_static;
use prometheus::{
    labels, opts, register_counter, register_gauge, register_histogram_vec,
    Counter, Encoder, Gauge, HistogramVec, IntCounter, IntGauge, Opts,
    Registry, TextEncoder,
};
use tokio::sync::mpsc;
use std::{thread, time};
use std::time::{SystemTime, UNIX_EPOCH};


pub const PROMETHEUS_PORT: u16 = 9001;

// These are our prometheus metrics
// UID_DEVICES : gauge (how many devices are we watching)
// SUCCSFULL_POLLS : counter
// FAILED_POLLS : counter
lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref SUCCESSFUL_POLLS: IntCounter =
        IntCounter::new("crmx_successful_polls", "RDM polls successful")
            .expect("metric can be created");
    pub static ref FAILED_POLLS: IntCounter =
    IntCounter::new("crmx_failed_polls", "RDM polls failed")
        .expect("metric can be created");
    pub static ref UID_DEVICES: IntGauge =
    IntGauge::new("crmx_uid_devices", "How many UIDs are we polling")
        .expect("metric can be created");
}

fn register_custom_metrics() {
    REGISTRY
        .register(Box::new(SUCCESSFUL_POLLS.clone()))
        .expect("collector can be registered");
    REGISTRY
        .register(Box::new(FAILED_POLLS.clone()))
        .expect("collector can be registered");    
    REGISTRY
        .register(Box::new(UID_DEVICES.clone()))
        .expect("collector can be registered");            
}

/// This is the prometheus request server (that is: the thing prometheus connects to to collect metrics)
async fn serve_req(
    _req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&REGISTRY.gather(), &mut buffer) {
        eprintln!("could not encode custom metrics: {}", e);
    };
    let mut res = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("custom metrics could not be from_utf8'd: {}", e);
            String::default()
        },
    };
    buffer.clear();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        eprintln!("could not encode prometheus metrics: {}", e);
    };
    let res_custom = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("prometheus metrics could not be from_utf8'd: {}", e);
            String::default()
        },
    };
    buffer.clear();

    res.push_str(&res_custom);

    let response = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(Body::from(res))
        .unwrap();

    Ok(response)
}

async fn run_prometheus() {
    let addr = ([127, 0, 0, 1], PROMETHEUS_PORT).into(); // Listen on port 9898 for prometheus, which will hit http://localhost:9898/metrics but we actually serve the same to all URLs
    info!("Listening on http://{}", addr);

    let serve_future = Server::bind(&addr).serve(make_service_fn(|_| async {
        Ok::<_, hyper::Error>(service_fn(serve_req))
    }));

    if let Err(err) = serve_future.await {
        error!("server error: {}", err);
    }
}

// All of the multicast code is lifted from this repo: https://github.com/bluejekyll/multicast-example
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::time::Duration;
use std::str;

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
fn lumen_nova_transport_gen(data: &[u8], uid_thing: [u8; 6]) -> Option<Vec<u8>> {
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
            uid_thing : uid_thing,
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
                            debug!("None found {:?}",resp.uid_found);
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
            uid_thing : uid_thing,
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



fn lumen_nova_transport_7c(data: &[u8]) -> Option<Vec<u8>> {
    lumen_nova_transport_gen(data, [0x7c, 0xf2, 0x0b, 0x00, 0x55, 0x4c])
}

fn lumen_nova_transport_7b(data: &[u8]) -> Option<Vec<u8>> {
    lumen_nova_transport_gen(data, [0x7b, 0xf2, 0x0b, 0x00, 0x55, 0x4c])
}

async fn run_crmx() {
    let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    let mut con = client.get_connection().unwrap();

    let mut tn : u8 = 0;

    let my_uid = Uid::new(0x4c55,0x000bf280);

    loop {

        let uid_set : Vec<String> = redis::cmd("SMEMBERS")
        .arg("crmx_uids")
        .query(&mut con)
        .unwrap();

        let mut uids : Vec<Uid> = Vec::new();

        for uid in uid_set {
            uids.push(Uid::from_string(uid));
        }

        UID_DEVICES.set(uids.len().try_into().unwrap_or(0x00));

        for uid in uids {
            
            thread::sleep(time::Duration::from_secs(5));

            tn = tn.overflowing_add(1).0;

            let mut output_pkt = Pkt::new();

            output_pkt.destination = uid.clone();
            output_pkt.source = my_uid.clone();
        
            output_pkt.tn = tn;
        
            output_pkt.port_or_response_type = 0x01;
        
            output_pkt.cc = GET_COMMAND;
        
            output_pkt.pid = SENSOR_VALUE;
        
            output_pkt.pdl = 0x01;
        
            output_pkt.pd.push(0x01); // Sensor 1 is temperature
        
            output_pkt.set_message_length(); // sets message length from PDL
            output_pkt.set_checksum(); // sets checksum from the whole packet.
        
            // debug!("{:?}",lumen_nova_transport_gen(output_pkt.serialize().as_slice(),[0x7c, 0xf2, 0x0b, 0x00, 0x55, 0x4c]).unwrap().hex_dump()); // send device_info
            
            let uid_thing_string : String = redis::cmd("HGET").arg(uid.to_string()).arg("lumen_nova_id").query(&mut con).unwrap();

            let uid_thing_vec = hex::decode(uid_thing_string).unwrap();

            let mut uid_thing : [u8; 6] = [0; 6];

            for i in 0..uid_thing_vec.len() {
                uid_thing[i] = uid_thing_vec[i];
            }

            // info!("{:X?}",uid_thing);

            match lumen_nova_transport_gen(output_pkt.serialize().as_slice(),uid_thing) {
                    Some(data_vec) => {
                        match Pkt::deserialize(data_vec) {
                            None => {
                                FAILED_POLLS.inc();
                                continue;
                            },
                            Some(pkt) => {
                                match SensorValuePD::deserialize(pkt.pd) {
                                    None =>  {
                                        FAILED_POLLS.inc();
                                        continue;
                                    },
                                    Some(pd) => {
                                        SUCCESSFUL_POLLS.inc();
                                        let _ : () = redis::cmd("HSET").arg(uid.to_string()).arg("temp_value").arg(pd.present).query(&mut con).unwrap(); // set the current value
                                        let _ : () = redis::cmd("HSET").arg(uid.to_string()).arg("temp_ts").arg(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()).query(&mut con).unwrap(); // set the current value                
                                    }
                                }
                            }
                        }
                    },
                    None => {
                        FAILED_POLLS.inc();
                        continue;
                    }
            }
          
        
            
        }

        debug!("Loooop!");

    }

}

#[tokio::main]
pub async fn main() {
    // Statements here are executed when the compiled binary is called

    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ), // Filter to debug, output to termial
    ])
    .unwrap();

    register_custom_metrics();

    // Print text to the console
    debug!("Hello World!");

    tokio::spawn(async {
        run_prometheus().await;
    });

    run_crmx().await;

    // // 4c55:000bf280
    // let my_uid = Uid::new(0x4c55,0x000bf280);

    // // let mut all_uids_found = do_discovery_algo(lumen_nova_transport_7c,&my_uid,true,true);

    // // all_uids_found.extend(do_discovery_algo(lumen_nova_transport_7b,&my_uid,true,true));

    // // info!("All uids: {:?}",all_uids_found);

    // // all_uids_found.extend(do_discovery_algo(lumen_nova_transport_7c,&my_uid,false,true));
    // // all_uids_found.extend(do_discovery_algo(lumen_nova_transport_7b,&my_uid,false,true));

    // // info!("All uids: {:?}",all_uids_found);

    // let mut output_pkt = Pkt::new();

    // output_pkt.destination = Uid::new(0x3638,0x2710_6d51);
    // output_pkt.source = my_uid.clone();
    
    // let mut tn = 0;

    // output_pkt.tn = tn;

    // output_pkt.port_or_response_type = 0x01;

    // output_pkt.cc = GET_COMMAND;

    // output_pkt.pid = DEVICE_LABEL;

    // output_pkt.pdl = 0x00;

    // // output_pkt.pd.push(0x01);

    // output_pkt.set_message_length(); // sets message length from PDL
    // output_pkt.set_checksum(); // sets checksum from the whole packet.

    // // debug!("{:?}",lumen_nova_transport_gen(output_pkt.serialize().as_slice(),[0x7c, 0xf2, 0x0b, 0x00, 0x55, 0x4c]).unwrap().hex_dump()); // send device_info
    
    // let response_pkt = Pkt::deserialize(lumen_nova_transport_gen(output_pkt.serialize().as_slice(),[0x7c, 0xf2, 0x0b, 0x00, 0x55, 0x4c]).unwrap()).unwrap();
    
    // // let response_pd = SensorDefinitionPD::deserialize(response_pkt.pd).unwrap();

    // debug!("{:?}",str::from_utf8(&response_pkt.pd[..]).unwrap());

    // output_pkt.tn = output_pkt.tn.overflowing_add(1).0;
    // output_pkt.destination = Uid::new(0x3638,0x2710_6d38);
    // output_pkt.set_message_length(); // sets message length from PDL
    // output_pkt.set_checksum(); // sets checksum from the whole packet.

    // let response_pkt = Pkt::deserialize(lumen_nova_transport_gen(output_pkt.serialize().as_slice(),[0x7c, 0xf2, 0x0b, 0x00, 0x55, 0x4c]).unwrap()).unwrap();
    
    // debug!("{:?}",str::from_utf8(&response_pkt.pd[..]).unwrap());

    // output_pkt.tn = output_pkt.tn.overflowing_add(1).0;
    // output_pkt.destination = Uid::new(0x3638,0x2710_6d26);
    // output_pkt.set_message_length(); // sets message length from PDL
    // output_pkt.set_checksum(); // sets checksum from the whole packet.

    // let response_pkt = Pkt::deserialize(lumen_nova_transport_gen(output_pkt.serialize().as_slice(),[0x7b, 0xf2, 0x0b, 0x00, 0x55, 0x4c]).unwrap()).unwrap();
    
    // debug!("{:?}",str::from_utf8(&response_pkt.pd[..]).unwrap());
    
    // output_pkt.tn = output_pkt.tn.overflowing_add(1).0;
    // output_pkt.destination = Uid::new(0x3638,0x2710_6d2b);
    // output_pkt.set_message_length(); // sets message length from PDL
    // output_pkt.set_checksum(); // sets checksum from the whole packet.
    
    // let response_pkt = Pkt::deserialize(lumen_nova_transport_gen(output_pkt.serialize().as_slice(),[0x7b, 0xf2, 0x0b, 0x00, 0x55, 0x4c]).unwrap()).unwrap();
    
    // debug!("{:?}",str::from_utf8(&response_pkt.pd[..]).unwrap());

    // let mut output_pkt = Pkt::new();

    // output_pkt.destination = Uid::new(0x3638,0x2710_6d51);
    // output_pkt.source = my_uid.clone();
    
    // let mut tn = 0;

    // output_pkt.tn = tn;

    // output_pkt.port_or_response_type = 0x01;

    // output_pkt.cc = GET_COMMAND;

    // output_pkt.pid = SENSOR_VALUE;

    // output_pkt.pdl = 0x01;

    // output_pkt.pd.push(0x01);

    // output_pkt.set_message_length(); // sets message length from PDL
    // output_pkt.set_checksum(); // sets checksum from the whole packet.

    // // debug!("{:?}",lumen_nova_transport_gen(output_pkt.serialize().as_slice(),[0x7c, 0xf2, 0x0b, 0x00, 0x55, 0x4c]).unwrap().hex_dump()); // send device_info
    
    // let response_pkt = Pkt::deserialize(lumen_nova_transport_gen(output_pkt.serialize().as_slice(),[0x7c, 0xf2, 0x0b, 0x00, 0x55, 0x4c]).unwrap()).unwrap();
    
    // let response_pd = SensorValuePD::deserialize(response_pkt.pd).unwrap();

    // debug!("{:?}",response_pd);

    // output_pkt.tn = output_pkt.tn.overflowing_add(1).0;
    // output_pkt.destination = Uid::new(0x3638,0x2710_6d38);
    // output_pkt.set_message_length(); // sets message length from PDL
    // output_pkt.set_checksum(); // sets checksum from the whole packet.

    // let response_pkt = Pkt::deserialize(lumen_nova_transport_gen(output_pkt.serialize().as_slice(),[0x7c, 0xf2, 0x0b, 0x00, 0x55, 0x4c]).unwrap()).unwrap();
    
    // let response_pd = SensorValuePD::deserialize(response_pkt.pd).unwrap();

    // debug!("{:?}",response_pd);

    // output_pkt.tn = output_pkt.tn.overflowing_add(1).0;
    // output_pkt.destination = Uid::new(0x3638,0x2710_6d26);
    // output_pkt.set_message_length(); // sets message length from PDL
    // output_pkt.set_checksum(); // sets checksum from the whole packet.

    // let response_pkt = Pkt::deserialize(lumen_nova_transport_gen(output_pkt.serialize().as_slice(),[0x7b, 0xf2, 0x0b, 0x00, 0x55, 0x4c]).unwrap()).unwrap();
    
    // let response_pd = SensorValuePD::deserialize(response_pkt.pd).unwrap();

    // debug!("{:?}",response_pd);
    
    // output_pkt.tn = output_pkt.tn.overflowing_add(1).0;
    // output_pkt.destination = Uid::new(0x3638,0x2710_6d2b);
    // output_pkt.set_message_length(); // sets message length from PDL
    // output_pkt.set_checksum(); // sets checksum from the whole packet.
    
    // let response_pkt = Pkt::deserialize(lumen_nova_transport_gen(output_pkt.serialize().as_slice(),[0x7b, 0xf2, 0x0b, 0x00, 0x55, 0x4c]).unwrap()).unwrap();
    
    // let response_pd = SensorValuePD::deserialize(response_pkt.pd).unwrap();

    // debug!("{:?}",response_pd);

    // // 36 38 27 10 6d 51 is over on 7c
    // // 36 38 27 10 6d 38 on 7c

    // // 36 38 27 10 6d 26 on 7d
    // // 36 38 27 10 6d 2b on 7d


}