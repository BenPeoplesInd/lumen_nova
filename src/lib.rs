use e1_20;

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_hex::*;

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }


    #[test]
    fn lnpkt_ser_des() {
        let mut test_packet =  LNPkt { 
            dst: [0;6], 
            src: [0;6], 
            seq: 0, 
            is_response: 0, 
            length: 0, 
            command: 0, 
            data: Vec::new() 
        };

        test_packet.dst = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        test_packet.src = [0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];

        test_packet.seq = 0x55;

        test_packet.is_response = 3;

        test_packet.length = 5;
        test_packet.command = 32;

        println!("{:?}",test_packet);

        let data = test_packet.serialize();

        println!("{:?}",data.hex_dump());

        let test_packet_new = LNPkt::deserialize(&data);

        println!("{:?}",test_packet_new);

    }

}


/// LumenNova Packet
/// there's a "BB" header and then a 0x00 0x00 pad after the addresses, but not modeled her
/// 
/// 8-bit commands known:
/// 0x03 = RDM packet?
/// 0x64 = RDM discovery response?
/// 0x72 = RDM normal response?
#[derive(Debug)]
pub struct LNPkt {
    // "BB"
    pub dst : [u8; 6],
    pub src : [u8; 6],
    // NUL NUL
    // 2a (*) -- it's funny becuase it's like a tiny supernova in each packet
    pub seq : u8,
    // 0x01 version number
    pub is_response : u8, // 0x00 = not a response, 0x01 = is response
    pub length : u16, // total length of bytes following this octet
    pub command : u8, // 8-bit command? 
    pub data : Vec<u8> // so realistically, this should be an Option of the various types.
}

impl LNPkt {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        data.push('B' as u8);
        data.push('B' as u8);

        data.extend(self.dst);
        data.extend(self.src);

        data.push(0x00); // 14
        data.push(0x00); // 15
        data.push(0x2a); // 16

        data.push(self.seq); // 17
        data.push(0x01); // 18
        data.push(self.is_response); // 19
        data.extend(self.length.to_le_bytes()); // 20 21
        data.push(self.command); // 22
        data.extend(&self.data); 

        return data;
    }

    pub fn deserialize(data : &Vec<u8>) -> Option<LNPkt> {
        let mut rv = LNPkt::new();

        if data.len() < 23 {
            return None;
        }

        rv.dst.clone_from_slice(&data[2..8]);
        rv.src.clone_from_slice(&data[8..14]);

        rv.seq = data[17];
        rv.is_response = data[19];
        
        let u16_array : [u8; 2] = [data[20], data[21]];

        rv.length = u16::from_le_bytes(u16_array);

        rv.command = data[22];

        if data.len() > 23 {
            rv.data.extend(&data[23..]);
        }

        return Some(rv);
    }

    pub fn new() -> LNPkt {
        LNPkt { 
            dst: [0;6], 
            src: [0;6], 
            seq: 0, 
            is_response: 0, 
            length: 0, 
            command: 0, 
            data: Vec::new() 
        }
    }
}

/// This gets serialized into the data Vec in the LNPkt
/// commands known:
/// 0x4407 = RDM discovery packet?
#[derive(Debug)]
pub struct LNRdmDisc {
    pub command : u16,
    pub uid_thing : [u8; 6],
    pub rdm_packet : Vec<u8> // realistically this should be an actual RDM packet from e1_20::Pkt
}

impl LNRdmDisc {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend(self.command.to_be_bytes());
        data.extend(&self.uid_thing);
        data.extend(&self.rdm_packet);

        
        return data;
    }

    pub fn deserialize(data : &Vec<u8>) -> Option<LNRdmDisc> {
        let mut rv = LNRdmDisc {
            command : 0,
            uid_thing : [0; 6],
            rdm_packet : Vec::new()
        };

        if data.len() < 8 {
            return None;
        }

        let u16_array : [u8; 2] = [data[0], data[1]];


        rv.command = u16::from_be_bytes(u16_array);
        rv.uid_thing.clone_from_slice(&data[2..8]);
        
        if data.len() > 8 {
            rv.rdm_packet.extend_from_slice(&data[8..]);
        }

        return Some(rv);
    }
}

/// This gets serialized into the data Vec in the LNPkt
/// commands known:
/// 0x52 = RDM packet (it's a byte shorter, so a different serailized format?)
#[derive(Debug)]
pub struct LNRdmNormal {
    pub command : u8,
    pub uid_thing : [u8; 6],
    pub rdm_packet : Vec<u8>
}

impl LNRdmNormal {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        data.push(self.command);
        data.extend(self.uid_thing);
        data.extend(&self.rdm_packet);
        
        return data;
    }

    pub fn deserialize(data : &Vec<u8>) -> Option<LNRdmNormal> {
        let mut rv = LNRdmNormal {
            command : 0,
            uid_thing : [0; 6],
            rdm_packet : Vec::new()
        };

        if data.len() < 7 {
            return None;
        }

        rv.command = data[0];
        rv.uid_thing.clone_from_slice(&data[1..7]);
        
        if data.len() > 7 {
            rv.rdm_packet.extend_from_slice(&data[7..]);
        }

        return Some(rv);
    }
}

// if command = 0x64
#[derive(Debug)]
pub struct LNRdmDiscResp {
    pub cmd : u8,
    pub data_found : u8, // 0x00 if no response, 0x01 if we got something, 0xff if we got one
    pub uid_found : [u8; 6]
}

impl LNRdmDiscResp {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        data.push(self.cmd);
        data.push(self.data_found);
        data.extend(self.uid_found);

        return data;
    }

    pub fn deserialize(data : &Vec<u8>) -> Option<LNRdmDiscResp> {
        let mut rv = LNRdmDiscResp {
            cmd: 0x00,
            data_found: 0x00,
            uid_found: [0; 6]
        };


        if data.len() < 8 {
            return None;
        }

        rv.cmd = data[0];
        rv.data_found = data[1];
        rv.uid_found.clone_from_slice(&data[2..8]);

        return Some(rv);
        
    }
}

// if command = 0x72
// I don't know if I need this as a struct since really we should just decode the packet.
#[derive(Debug)]
pub struct LNRdmRespNormal {
    pub rdm_packet : Vec<u8>
}
