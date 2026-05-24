# Patrick Turner
# CSC 842-DT1
# Dr. Welu
# 5/24/2026

# Watcher Lite 1.0

# Watcher lite is a lightweight system designed to sit behind a firewall to provide a second level of security for
# a local network.

# imported modules
import argparse
import logging
import os
import time
import threading
import requests
from collections import defaultdict
from datetime import datetime

# scapy modules for packet capture
from scapy.all import sniff, IP, TCP, UDP

# rich modules for ascii interface
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

# setup for logging alerts and warnings

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
	filename="logs/watcher_1_0.log",
	level=logging.INFO,
	format="%(asctime)s [%(levelname)s] %(message)s",
	datefmt="%Y-%m-%d %H:%M:%S",
	)
logger = logging.getLogger("sentinel")

# Configuration of port scan threshold and window

PORT_SCAN_THRESHOLD = 15	# number of ports scanned
PORT_SCAN_WINDOW    = 10	# time in seconds of port scan window

BAD_IPS = {
	"198.51.100.1",		# Add hardcoded IP address to alert on 
	"203.0.113.42",
	"192.168.0.135",
	}

# Maximum alerts to show in display
MAX_ALERTS_DISPLAY = 50


# Threat feed class

class ThreatFeed:
	FEED_URL = [
		"https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
			]

	def __init__(self, refresh_hours=2):
		self.bad_ips: set = set()
		self.refresh_hours = refresh_hours
		self.lock = threading.Lock()
		self.status = "Downloading..."
		self._load()
		self._schedule_refresh()

	def _load(self):
		new_ips = set()
		for url in self.FEED_URL:
			try:
				resp = requests.get(url, timeout=10)
				resp.raise_for_status()
				for line in resp.text.splitlines():
					line = line.strip()
					if line and not line.startswith("#"):
						new_ips.add(line)
			except Exception as e:
				logger.warning(f"Feed failed {url}: {e}")

		with self.lock:
			self.bad_ips = new_ips
			self.status = f"{len(self.bad_ips):,} IPs  •  last updated {datetime.now().strftime('%H:%M:%S')}"

		logger.info(f"ThreatFeed loaded {len(self.bad_ips)} IPs")

	def _schedule_refresh(self):
		t = threading.Timer(self.refresh_hours * 3600, self._refresh_loop)
		t.daemon = True
		t.start()

	def _refresh_loop(self):
		self.status = "Refreshing..."
		self._load()
		self._schedule_refresh()

	def is_bad(self, ip: str) -> bool:
		with self.lock:
			return ip in self.bad_ips

# Load local malicious IP addresses from bad_ips.txt

def load_malicious_ips(filepath: str = "bad_ips.txt") -> set:
	ips = set(BAD_IPS)
	try:
		with open(filepath) as f:
			for line in f:
				line = line.strip()
				if line and not line.startswith("#"):
					ips.add(line)
	except FileNotFoundError:
		pass
	return ips

# Detector state class

class DetectorState:

	# Central store for all detection data and dashboard stats

	def __init__(self, malicious_ips: set, threat_feed: ThreatFeed):
		self.malicious_ips = malicious_ips
		self.threat_feed   = threat_feed

		# Port scan tracking: { src_ip: { port: timestamp } }
		self.port_hits: dict = defaultdict(dict)

		# Alert dedup sets
		self.alerted_scanners: set = set()
		self.alerted_bad_ips:  set = set()

		# Dashboard stats
		self.packet_count:   int  = 0
		self.alert_count:    int  = 0
		self.start_time:     float = time.time()

		# Alert log shown in the dashboard (list of dicts)
		# Each entry: { time, level, message }
		self.alert_log: list = []
		self.log_lock = threading.Lock()

		# Top talkers: { ip: packet_count }
		self.ip_counts: dict = defaultdict(int)

	def add_alert(self, level: str, message: str):
		"""Record an alert for the dashboard and the log file."""
		entry = {
			"time":    datetime.now().strftime("%H:%M:%S"),
			"level":   level,
			"message": message,
			}
		with self.log_lock:
			self.alert_log.append(entry)
			if len(self.alert_log) > MAX_ALERTS_DISPLAY:
				self.alert_log.pop(0)
		self.alert_count += 1

		# Write to the log file
		if level == "ALERT":
			logger.warning(message)
		else:
			logger.info(message)

	def reset_old_hits(self, src_ip: str):
		now = time.time()
		self.port_hits[src_ip] = {
		p: ts for p, ts in self.port_hits[src_ip].items()
		if now - ts <= PORT_SCAN_WINDOW
				}

	def uptime(self) -> str:
		secs = int(time.time() - self.start_time)
		h, rem = divmod(secs, 3600)
		m, s   = divmod(rem, 60)
		return f"{h:02d}:{m:02d}:{s:02d}"

# Detect malicious IPs class

def detect_malicious_ip(packet, state: DetectorState):
	if not packet.haslayer(IP):
		return
	src, dst = packet[IP].src, packet[IP].dst

	for ip in (src, dst):
		if ip in state.alerted_bad_ips:
			continue
		in_local = ip in state.malicious_ips
		in_feed  = state.threat_feed.is_bad(ip)
		if in_local or in_feed:
			direction    = "FROM" if ip == src else "TO"
			source_label = "live feed" if in_feed else "local list"
			msg = f"Traffic {direction} malicious IP: {ip} [{source_label}]  ({src} → {dst})"
			state.add_alert("ALERT", msg)
			state.alerted_bad_ips.add(ip)


def detect_port_scan(packet, state: DetectorState):
	if not (packet.haslayer(IP) and packet.haslayer(TCP)):
		return
	src_ip    = packet[IP].src
	dst_port  = packet[TCP].dport
	tcp_flags = packet[TCP].flags

	if tcp_flags != 0x02:   # SYN only
		return

	state.port_hits[src_ip][dst_port] = time.time()
	state.reset_old_hits(src_ip)
	unique_ports = len(state.port_hits[src_ip])

	if unique_ports >= PORT_SCAN_THRESHOLD and src_ip not in state.alerted_scanners:
		msg = f"Port scan from {src_ip} — {unique_ports} unique ports in {PORT_SCAN_WINDOW}s"
		state.add_alert("ALERT", msg)
		state.alerted_scanners.add(src_ip)
	elif unique_ports < PORT_SCAN_THRESHOLD // 2:
		state.alerted_scanners.discard(src_ip)

# Packet handler class

def handle_packet(packet, state: DetectorState):
	state.packet_count += 1
	if packet.haslayer(IP):
		state.ip_counts[packet[IP].src] += 1
	detect_malicious_ip(packet, state)
	detect_port_scan(packet, state)

# Dashboard class

def build_dashboard(state: DetectorState) -> Layout:

	layout = Layout()

	layout.split_column(
	Layout(name="header", size=3),
	Layout(name="middle", size=12),
	Layout(name="alerts"),
	Layout(name="footer", size=3),
		)
	layout["middle"].split_row(
	Layout(name="stats"),
	Layout(name="talkers"),
		)

	# Header
	header_text = Text()
	header_text.append("⚡ Watcher Lite 1.0", style="bold bright_red")
	header_text.append("  |  ", style="dim white")
	header_text.append(f"Uptime: {state.uptime()}", style="cyan")
	header_text.append("  |  ", style="dim white")
	header_text.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style="dim white")
	layout["header"].update(Panel(header_text, style="bold red"))

	# Stats panel
	stats_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
	stats_table.add_column("Key",   style="dim cyan",   width=22)
	stats_table.add_column("Value", style="bold white", width=16)

	stats_table.add_row("Packets Analyzed",  f"{state.packet_count:,}")
	stats_table.add_row("Alerts Fired",      f"[bold red]{state.alert_count}[/]")
	stats_table.add_row("IPs Monitored",     f"{len(state.ip_counts):,}")
	stats_table.add_row("Port Scanners",     f"{len(state.alerted_scanners)}")
	stats_table.add_row("Blocked IPs Hit",   f"{len(state.alerted_bad_ips)}")
	stats_table.add_row("Scan Threshold",    f"{PORT_SCAN_THRESHOLD} ports/{PORT_SCAN_WINDOW}s")

	layout["stats"].update(Panel(stats_table, title="[bold cyan]Stats[/]", border_style="cyan"))

	# Top talkers
	talkers_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
	talkers_table.add_column("IP Address",   style="white",      width=18)
	talkers_table.add_column("Packets",      style="bold yellow", width=10, justify="right")

	top = sorted(state.ip_counts.items(), key=lambda x: x[1], reverse=True)[:8]
	for ip, count in top:
	# Highlight IPs that have been flagged
		ip_style = "bold red" if ip in state.alerted_bad_ips or ip in state.alerted_scanners else "white"
		talkers_table.add_row(f"[{ip_style}]{ip}[/]", str(count))

	layout["talkers"].update(Panel(talkers_table, title="[bold yellow]Top Talkers[/]", border_style="yellow"))

	# Alert log
	alerts_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1), expand=True)
	alerts_table.add_column("Time",    style="dim white",   width=10)
	alerts_table.add_column("Level",   width=9)
	alerts_table.add_column("Message", style="white")

	level_styles = {
	"ALERT":   "[bold red]⚠ ALERT[/]",
	"WARNING": "[yellow]⚡ WARN[/]",
	"INFO":    "[cyan]ℹ INFO[/]",
			}

	with state.log_lock:
	# Show newest alerts at the top
		for entry in reversed(state.alert_log):
			styled_level = level_styles.get(entry["level"], entry["level"])
			alerts_table.add_row(entry["time"], styled_level, entry["message"])

			layout["alerts"].update(Panel(
			alerts_table,
			title="[bold white]Alert Log[/]",
			border_style="white",
			))

	# Footer — threat feed status
	feed_text = Text()
	feed_text.append("🌐 Threat Feed: ", style="dim white")
	feed_text.append(state.threat_feed.status, style="green")
	feed_text.append("   |   ", style="dim white")
	feed_text.append("Log: logs/watcher_1_0.log", style="dim white")
	feed_text.append("   |   ", style="dim white")
	feed_text.append("Press Ctrl+C to stop", style="dim white")
	layout["footer"].update(Panel(feed_text, style="dim"))

	return layout

# Main function

def main():
	parser = argparse.ArgumentParser(description="Watcher Lite — live terminal dashboard")
	parser.add_argument("-i", "--interface", default=None,
		help="Network interface (e.g. eth0). Default: auto.")
	parser.add_argument("--pcap", default=None,
		help="Path to a .pcap file instead of live capture.")
	parser.add_argument("--bad-ips", default="bad_ips.txt",
		help="Path to local bad IPs file.")
	args = parser.parse_args()

	console = Console()

	# Startup
	console.print("\n[bold red]⚡ Watcher Lite[/] — starting up...\n")
	console.print("[cyan]Downloading threat feeds...[/]")

	threat_feed    = ThreatFeed(refresh_hours=2)
	malicious_ips  = load_malicious_ips(args.bad_ips)
	state          = DetectorState(malicious_ips, threat_feed)

	# Log startup info
	state.add_alert("INFO", f"Watcher Lite started — feed: {threat_feed.status}")
	state.add_alert("INFO", f"Local IPs loaded: {len(malicious_ips)}  |  "
                            f"Scan threshold: {PORT_SCAN_THRESHOLD} ports/{PORT_SCAN_WINDOW}s")

	def packet_callback(packet):
		handle_packet(packet, state)

	# Launch sniffer in background
	def start_sniffing():
		if args.pcap:
			sniff(offline=args.pcap, prn=packet_callback, store=False)
		else:
			sniff(iface=args.interface, prn=packet_callback, store=False)

	sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
	sniffer_thread.start()

	# Dashboard loop
	try:
		with Live(
			build_dashboard(state),
			console=console,
			refresh_per_second=2,    # redraw twice per second
			screen=True,             # take over full terminal screen
		) as live:
			while True:
				time.sleep(0.5)
				live.update(build_dashboard(state))

	except KeyboardInterrupt:
		console.print("\n[bold red]Stopped.[/]  "
			f"Packets analyzed: [cyan]{state.packet_count:,}[/]  |  "
			f"Alerts fired: [red]{state.alert_count}[/]")
		console.print(f"[dim]Full log saved to: logs/watcher_1_0.log[/]\n")
		logger.info(f"Session ended. Packets: {state.packet_count}, Alerts: {state.alert_count}")


if __name__ == "__main__":
	main()
