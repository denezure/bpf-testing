use aya::maps::Array;
use aya::{include_bytes_aligned, Bpf};
use aya::programs::{tc, SchedClassifier};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::io::AsyncBufReadExt;
use tokio::signal;

mod tap;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/bpf-testing"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/bpf-testing"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let mut tap = tap::Tap::new()?;

    update_ifindex(&mut bpf, tap.if_index())?;

    info!("Please admin-up interface {}... Press enter once done.", tap.name());
    wait_for_enter().await;

    info!("Adding clsact to {}", tap.name());
    tc::qdisc_add_clsact(tap.name())?;

    info!("Setting up tap program...");
    let _tap_egress_link = {
        info!("Fetching tap program...");
        let tap_egress_program: &mut SchedClassifier = bpf.program_mut("tap_egress").unwrap().try_into()?;

        info!("Loading tap program...");
        tap_egress_program.load()?;

        info!("Attaching tap program...");
        tap_egress_program.attach(tap.name(), aya::programs::TcAttachType::Egress)?
    };

    info!("tap program is set up. Press enter to proceed with {} interface...", opt.iface);
    wait_for_enter().await;

    info!("Skipping adding clsact to {}", opt.iface);
    tc::qdisc_add_clsact(&opt.iface)?;

    info!("Setting up phys program...");
    let _phys_ingress_link = {
        info!("Fetching phys program...");
        let phys_ingress_program: &mut SchedClassifier = bpf.program_mut("phys_ingress").unwrap().try_into()?;

        info!("Loading phys program...");
        phys_ingress_program.load()?;

        info!("Attaching phys program...");
        phys_ingress_program.attach(&opt.iface, aya::programs::TcAttachType::Ingress)?
    };

    tokio::task::spawn({
        let mut rx = tap.take_receiver().unwrap();
        async move {
            while let Some(p) = rx.recv().await {
                info!("RX'd packet - len {}...", p.len());
            }
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    tc::qdisc_detach_program(&opt.iface, aya::programs::TcAttachType::Ingress, "phys_ingress")?;

    Ok(())
}

fn update_ifindex(bpf: &mut Bpf, ifindex: u32) -> Result<(), anyhow::Error> {
    let mut ifindex_map = Array::try_from(bpf.map_mut("tc_target_ifindex")?)?;
    ifindex_map.set(0, ifindex, 0).map_err(Into::into)
}

async fn wait_for_enter() {
    let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
    let mut buffer = Vec::new();

    let _fut = reader.read_until(b'\n', &mut buffer).await;
}