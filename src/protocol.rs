use std::str::from_utf8;
use std::sync::Arc;

use aes::Aes128;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use log::info;
use packed_struct::{PackedStruct, PackedStructSlice};
use packed_struct::derive::PackedStruct;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const MAGIC_NUMBER: u16 = 0x2131;
const HEADER_SIZE: usize = std::mem::size_of::<PacketHeader>();
const MAX_BUFFER_SIZE: usize = 16000;
const HANDSHAKE_HEADER: PacketHeader = PacketHeader {
    pkt_format: MAGIC_NUMBER,
    pkt_length: 0x0020,
    __unknown__: 0xffffffff,
    device_id: 0xffffffff,
    stamp: 0xffffffff,
    checksum: [0u8; 16]
};

type Encryptor = cbc::Encryptor<Aes128>;
type Decryptor = cbc::Decryptor<Aes128>;


#[derive(PackedStruct, PartialEq, Debug, Clone)]
#[packed_struct(endian = "msb")]
pub(crate) struct PacketHeader {
    pub pkt_format: u16,
    pub pkt_length: u16,
    pub __unknown__: u32,
    pub device_id: u32,
    pub stamp: u32,
    pub checksum: [u8; 16]
    //payload [u8] of unknown length
}

pub(crate) enum PacketType {
    Handshake,
    Generic
}

#[derive(Debug)]
pub enum ProtoError {
    SocketError(String),
    SendError(String),
    ReceiveError(String),
    PackError(String),
    UnpackError(String),
    Utf8Conversion(String),
    InvalidPacket(String),
    Encryption(String),
    Decryption(String)
}

//init vector = md5(md5(token) + token)
pub(crate) fn cbc_init_vector(token: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let key: [u8; 16] = md5::compute(token).as_slice().try_into().expect("Key must be 16 bytes");
    let mut iv = key.to_vec();
    iv.extend(token);

    let iv = md5::compute(&iv).as_slice().try_into().expect("IV must be 16 bytes");

    (key, iv)
}

fn encode(key: &[u8; 16], iv: &[u8; 16], payload: &str) -> Result<Vec<u8>, ProtoError> {
    let bytes = Encryptor::new_from_slices(key, iv)
        .map_err(|e| ProtoError::Encryption(e.to_string()))?
        .encrypt_padded_vec_mut::<Pkcs7>(&payload.as_bytes().to_vec());

    Ok(bytes.to_vec())
}

fn decode(key: &[u8; 16], iv: &[u8; 16], payload: &mut [u8]) -> Result<Vec<u8>, ProtoError> {
    let bytes = Decryptor::new_from_slices(key, iv)
        .map_err(|e| ProtoError::Encryption(e.to_string()))?
        .decrypt_padded_vec_mut::<Pkcs7>(payload)
        .map_err(|e| ProtoError::Decryption(e.to_string()))?;

    Ok(bytes)
}

pub(crate) async fn send(socket: Arc<TcpStream>,
                         pkt_type: PacketType,
                         device_id: u32,
                         key: &[u8; 16],
                         iv: &[u8; 16],
                         stamp: u32,
                         payload: &str) -> Result<(), ProtoError> {
    let payload = encode(key, iv, payload)?;
    let data = match pkt_type {
        PacketType::Handshake => HANDSHAKE_HEADER,
        PacketType::Generic => PacketHeader {
            pkt_format: MAGIC_NUMBER,
            pkt_length: (payload.len() + 32) as u16,
            __unknown__: 0,
            device_id,
            stamp,
            checksum: [0u8; 16],
        }
    };

    let mut pkt = data.pack_to_vec().map_err(|e| ProtoError::PackError(e.to_string()))?;
    let mut pkt_with_payload = pkt.clone();
    pkt_with_payload.extend(&payload);

    let checksum = md5::compute(pkt_with_payload);
    pkt.extend(&checksum.0);
    pkt.extend(&payload);

    let mut socket_clone = socket.clone();
    socket_clone.write_all(&pkt).await.map_err(|e| ProtoError::SendError(e.to_string()))?;
    info!("Sent {} bytes", pkt.len());

    Ok(())
}

pub(crate) async fn receive(mut socket: Arc<TcpStream>,
                            key: &[u8; 16],
                            iv: &[u8; 16]) -> Result<(PacketHeader, String), ProtoError> {
    let mut buf= vec![0u8; MAX_BUFFER_SIZE];
    let mut header = [0u8; HEADER_SIZE];

    socket.read_exact(&mut header).await.map_err(|e| ProtoError::ReceiveError(e.to_string()))?;
    info!("Received header bytes");

    let pkt = PacketHeader::unpack(&header).map_err(|e| ProtoError::UnpackError(e.to_string()))?;
    let payload_length = pkt.pkt_length as usize - HEADER_SIZE;
    buf.resize(payload_length, 0);
    socket.read_exact(&mut buf).await.map_err(|e| ProtoError::ReceiveError(e.to_string()))?;

    info!("Received payload");

    let payload = decode(key, iv, &mut buf)?;
    let payload = from_utf8(&payload).map_err(|e| ProtoError::Utf8Conversion(e.to_string()))?;

    info!("Received {} bytes", pkt.pkt_length);

    Ok((pkt, payload.to_string()))
}

#[cfg(test)]
mod tests {
    use std::str::from_utf8;

    use packed_struct::{PackedStruct, PackedStructSlice};

    use crate::protocol::{cbc_init_vector, decode, encode, HANDSHAKE_HEADER, PacketHeader};

    #[tokio::test]
    async fn test_packet_structure() {
        let packet = HANDSHAKE_HEADER;
        let mut header = [0u8; 32];
        packet.pack_to_slice(&mut header).expect("Cannot pack");
        let unpacked = PacketHeader::unpack(&header).unwrap();

        assert_eq!(packet, unpacked);
    }

    #[test]
    fn test_cbc_init_vector() {
        let token = [0u8; 16];
        let (key, iv) = cbc_init_vector(&token);

        assert_eq!(key.len(), 16);
        assert_eq!(iv.len(), 16);
    }

    #[test]
    fn test_encode_decode() {
        let key = [0u8; 16];
        let iv = [1u8; 16];
        let message = "Hello, World!";
        let mut encrypted = encode(&key, &iv, message).expect("Cannot encrypt");
        let decrypted = decode(&key, &iv, &mut encrypted)
            .expect("Cannot decrypt");
        let decrypted_str = from_utf8(&decrypted).unwrap();

        assert_eq!(message, decrypted_str);
    }
}
