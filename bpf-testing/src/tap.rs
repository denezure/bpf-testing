use std::{sync::Arc, thread::JoinHandle};

use nix::net::if_::if_nametoindex;
use tokio::sync::mpsc::{Receiver, Sender};
use tun_tap::{Iface, Mode};

pub struct Tap {
    if_index: u32,
    iface: Arc<Iface>,
    reader_handle: JoinHandle<()>,
    writer_handle: JoinHandle<()>,
    tx_sender: Sender<Vec<u8>>,
    rx_receiver: Option<Receiver<Vec<u8>>>,
}

impl Tap {
    pub fn new() -> anyhow::Result<Self> {
        let iface = Arc::new(Iface::without_packet_info("tap%d", Mode::Tap)?);

        let (tx_sender, tx_receiver) = tokio::sync::mpsc::channel(256);
        let (rx_sender, rx_receiver) = tokio::sync::mpsc::channel(256);

        let reader_handle = std::thread::spawn({
            let iface = iface.clone();
            move || {
                tap_reader(iface, rx_sender);
            }
        });

        let writer_handle = std::thread::spawn({
            let iface = iface.clone();
            move || {
                tap_writer(iface, tx_receiver);
            }
        });

        let if_index = if_nametoindex(iface.name())?;

        Ok(Self {
            if_index,
            iface,
            reader_handle,
            writer_handle,
            tx_sender,
            rx_receiver: Some(rx_receiver),
        })
    }

    pub fn if_index(&self) -> u32 {
        self.if_index
    }

    pub fn name(&self) -> &str {
        self.iface.name()
    }

    pub fn get_sender(&self) -> Sender<Vec<u8>> {
        self.tx_sender.clone()
    }

    pub fn take_receiver(&mut self) -> Option<Receiver<Vec<u8>>> {
        self.rx_receiver.take()
    }
}

fn tap_reader(iface: Arc<Iface>, ch: Sender<Vec<u8>>) {
    loop {
        let mut buf = vec![0u8; 1536];

        match iface.recv(&mut buf[..]) {
            Ok(n) => {
                buf.resize(n, 0);
                match ch.blocking_send(buf) {
                    Ok(_) => {},
                    Err(_) => return,
                }
            },
            Err(_) => return,
        }
    }
}

fn tap_writer(iface: Arc<Iface>, mut ch: Receiver<Vec<u8>>) {
    while let Some(v) = ch.blocking_recv() {
        match iface.send(&v[..]) {
            Ok(_) => {},
            Err(_) => return,
        }
    }
}
