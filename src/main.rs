use ctrlc;
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, SystemTime};

#[derive(Debug)]
enum FlowTrackerError {
    ParseError(String),
    ChannelError(String),
    CaptureError(String),
}

impl std::fmt::Display for FlowTrackerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FlowTrackerError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            FlowTrackerError::ChannelError(msg) => write!(f, "Channel error: {}", msg),
            FlowTrackerError::CaptureError(msg) => write!(f, "Capture error: {}", msg),
        }
    }
}

impl Error for FlowTrackerError {}

// Structure to represent a network flow
#[derive(Hash, Eq, PartialEq, Clone)]
struct Flow {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

// Structure to track flow statistics
#[derive(Clone)]
struct FlowStats {
    packet_count: u64,
    byte_count: u64,
    start_time: SystemTime,
    last_seen: SystemTime,
}

// Message type for thread communication
struct PacketInfo {
    flow: Flow,
    bytes: u64,
}

impl FlowStats {
    fn new() -> Self {
        let now = SystemTime::now();
        FlowStats {
            packet_count: 1,
            byte_count: 0,
            start_time: now,
            last_seen: now,
        }
    }
}

struct FlowTracker {
    flows: HashMap<Flow, FlowStats>,
}

impl FlowTracker {
    fn new() -> Self {
        FlowTracker {
            flows: HashMap::new(),
        }
    }

    fn update_flow(&mut self, flow: Flow, bytes: u64) {
        let now = SystemTime::now();

        if let Some(stats) = self.flows.get_mut(&flow) {
            stats.packet_count += 1;
            stats.byte_count += bytes;
            stats.last_seen = now;
        } else {
            let mut stats = FlowStats::new();
            stats.byte_count = bytes;
            self.flows.insert(flow, stats);
        }
    }

    fn print_stats(&self) {
        println!("\n=== Current Flow Statistics ===");
        println!(
            "{:<20} {:<20} {:<10} {:<10} {:<10} {:<15} {:<15} {:<15}",
            "Source IP",
            "Destination IP",
            "Src Port",
            "Dst Port",
            "Protocol",
            "Packets",
            "Bytes",
            "Duration(s)"
        );

        for (flow, stats) in &self.flows {
            let duration = stats
                .last_seen
                .duration_since(stats.start_time)
                .unwrap_or(Duration::from_secs(0))
                .as_secs();

            println!(
                "{:<20} {:<20} {:<10} {:<10} {:<10} {:<15} {:<15} {:<15}",
                flow.src_ip.to_string(),
                flow.dst_ip.to_string(),
                flow.src_port,
                flow.dst_port,
                flow.protocol,
                stats.packet_count,
                stats.byte_count,
                duration
            );
        }
    }
}

fn packet_parser_thread(
    rx: Receiver<Vec<u8>>,
    running: Arc<AtomicBool>,
) -> Result<Receiver<PacketInfo>, Box<dyn Error>> {
    let (tx, rx_main) = channel();
    thread::spawn(move || {
        while running.load(Ordering::Relaxed) {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(packet_data) => {
                    if let Ok(flow) = parse_packet(&packet_data) {
                        let packet_info = PacketInfo {
                            flow,
                            bytes: packet_data.len() as u64,
                        };
                        if tx.send(packet_info).is_err() {
                            eprintln!("Error sending parsed packet info");
                            break;
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    });

    Ok(rx_main)
}

fn stats_thread(
    rx_parsed: Receiver<PacketInfo>,
    running: Arc<AtomicBool>,
) -> Result<(), FlowTrackerError> {
    let mut flow_tracker = FlowTracker::new();
    let mut last_print = SystemTime::now();
    let print_interval = Duration::from_secs(5);

    while running.load(Ordering::Relaxed) {
        // TODO: Get rid of timeout for a sentinel value of empty packet info
        match rx_parsed.recv_timeout(Duration::from_millis(100)) {
            Ok(packet_info) => {
                flow_tracker.update_flow(packet_info.flow, packet_info.bytes);

                if SystemTime::now()
                    .duration_since(last_print)
                    .unwrap_or(Duration::from_secs(0))
                    >= print_interval
                {
                    flow_tracker.print_stats();
                    last_print = SystemTime::now();
                }
            }
            Err(_) => continue,
        }
    }

    // Final statistics print before shutdown
    flow_tracker.print_stats();
    println!("\nStats thread shutting down...");
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Setup shutdown signal handling
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("\nShutting down...");
        r.store(false, Ordering::Relaxed);
    })?;

    // Find the default device
    let default_device = Device::lookup()?.ok_or(FlowTrackerError::CaptureError(
        "No default device found".to_string(),
    ))?;

    println!("Using device: {}", default_device.name);

    // Create a new capture handle
    let mut cap = Capture::from_device(default_device)?
        .promisc(true)
        .snaplen(65535)
        .immediate_mode(true)
        .open()?;

    // Set filter for TCP and UDP traffic
    cap.filter("tcp or udp", true)?;

    // Create channels for communication between threads
    let (tx_parser, rx_parser) = channel();
    let rx_main = packet_parser_thread(rx_parser, running.clone())?;

    println!("Starting flow tracking. Press Ctrl+C to stop.");

    // Spawn stats thread
    let stats_handle = {
        let running = running.clone();
        thread::spawn(move || stats_thread(rx_main, running))
    };

    // Main capture loop with error recovery
    while running.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                if tx_parser.send(packet.data.to_vec()).is_err() {
                    eprintln!("Error sending packet data to parser thread");
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("Capture error: {}", e);
                // Attempt to recover by reopening capture
                match Capture::from_device(Device::lookup()?.ok_or("No device")?)?.open() {
                    Ok(new_cap) => {
                        cap = new_cap;
                        println!("Successfully recovered capture");
                    }
                    Err(e) => {
                        eprintln!("Failed to recover capture: {}", e);
                        break;
                    }
                }
            }
        }
    }

    // Wait for stats thread
    if let Err(e) = stats_handle.join() {
        eprintln!("Error joining stats thread: {:?}", e);
    }

    println!("Shutdown complete.");
    Ok(())
}

fn parse_packet(packet: &[u8]) -> Result<Flow, Box<dyn Error>> {
    // Skip Ethernet header (14 bytes)
    let ip_header = &packet[14..];

    // Get IP version from first nibble
    let version = (ip_header[0] >> 4) & 0xF;

    let (src_ip, dst_ip, protocol, header_length) = match version {
        4 => {
            // IPv4
            let header_length = ((ip_header[0] & 0xF) * 4) as usize;
            let protocol = ip_header[9];
            let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                ip_header[12],
                ip_header[13],
                ip_header[14],
                ip_header[15],
            ));
            let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                ip_header[16],
                ip_header[17],
                ip_header[18],
                ip_header[19],
            ));
            (src_ip, dst_ip, protocol, header_length)
        }
        6 => {
            // IPv6 (simplified)
            let protocol = ip_header[6];
            let src_ip = IpAddr::V6(std::net::Ipv6Addr::new(
                ((ip_header[8] as u16) << 8) | ip_header[9] as u16,
                ((ip_header[10] as u16) << 8) | ip_header[11] as u16,
                ((ip_header[12] as u16) << 8) | ip_header[13] as u16,
                ((ip_header[14] as u16) << 8) | ip_header[15] as u16,
                ((ip_header[16] as u16) << 8) | ip_header[17] as u16,
                ((ip_header[18] as u16) << 8) | ip_header[19] as u16,
                ((ip_header[20] as u16) << 8) | ip_header[21] as u16,
                ((ip_header[22] as u16) << 8) | ip_header[23] as u16,
            ));
            let dst_ip = IpAddr::V6(std::net::Ipv6Addr::new(
                ((ip_header[24] as u16) << 8) | ip_header[25] as u16,
                ((ip_header[26] as u16) << 8) | ip_header[27] as u16,
                ((ip_header[28] as u16) << 8) | ip_header[29] as u16,
                ((ip_header[30] as u16) << 8) | ip_header[31] as u16,
                ((ip_header[32] as u16) << 8) | ip_header[33] as u16,
                ((ip_header[34] as u16) << 8) | ip_header[35] as u16,
                ((ip_header[36] as u16) << 8) | ip_header[37] as u16,
                ((ip_header[38] as u16) << 8) | ip_header[39] as u16,
            ));
            (src_ip, dst_ip, protocol, 40)
        }
        _ => return Err("Unsupported IP version".into()),
    };

    // Parse TCP/UDP header
    let transport_header = &ip_header[header_length..];
    let src_port = ((transport_header[0] as u16) << 8) | transport_header[1] as u16;
    let dst_port = ((transport_header[2] as u16) << 8) | transport_header[3] as u16;

    Ok(Flow {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
    })
}
