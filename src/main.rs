use env_logger::Env;
use log::{error, info};
use crate::device::Device;

mod protocol;
mod device;
mod payload;

#[tokio::main]
async fn main() {
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let device = Device::connect("172.16.0.17:58867", &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]).await.expect("Error connecting to device");

    info!("test");
}
