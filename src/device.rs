use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use log::info;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::protocol::{cbc_init_vector, PacketHeader, PacketType, ProtoError, receive, send};

pub struct Device {
    device_id: u32,
    cbc_key: [u8; 16],
    cbc_iv: [u8; 16],
    socket: Arc<UdpSocket>,
    stamp: AtomicU32
}

impl Device {
    pub async fn connect(addr: &str, token: &[u8; 16]) -> Result<Self, ProtoError> {
        let socket = TcpStream::connect(addr).await
            .map_err(|e| ProtoError::SocketError(e.to_string()))?;

        info!("Connected to {}", addr);

        let (cbc_key, cbc_iv) = cbc_init_vector(token);
        let mut device = Device {
            device_id: 0xffffffff, //we need to initialize generic device_id for handshake packet
            cbc_key,
            cbc_iv,
            socket: Arc::new(socket),
            stamp: AtomicU32::new(0)
        };

        device.handshake().await?;

        Ok(device)
    }

    async fn handshake(&mut self) -> Result<(), ProtoError> {
        info!("Sending handshake...");
        send(
            self.socket.clone(),
            PacketType::Handshake,
            self.device_id,
            &self.cbc_key,
            &self.cbc_iv,
            0xffffffff,
            ""
        ).await?;

        info!("Awaiting response...");
        let (pkt, _) = receive(self.socket.clone(), &self.cbc_key, &self.cbc_iv).await?;
        info!("Received handshake response");

        self.device_id = pkt.device_id;
        self.stamp = AtomicU32::new(pkt.stamp);

        Ok(())
    }

    pub async fn exchange(&self, payload: &str) -> Result<(PacketHeader, String), ProtoError> {
        send(
            self.socket.clone(),
            PacketType::Generic,
            self.device_id,
            &self.cbc_key,
            &self.cbc_iv,
            self.stamp.fetch_add(1, Ordering::SeqCst) + 1,
            payload
        ).await?;
        receive(self.socket.clone(), &self.cbc_key, &self.cbc_iv).await
    }
}
