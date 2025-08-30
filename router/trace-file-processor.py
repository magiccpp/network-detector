import argparse
from collections import defaultdict
import glob
import os
import subprocess
import sys
from datetime import datetime, timezone
import time
import json
import psycopg2
import asyncio
import aiohttp
from scapy.all import rdpcap, IP
from prometheus_client import Counter, start_http_server

# Define Prometheus metrics
gateway_received_bytes_total = Counter(
    'dynamic_routing_gateway_received_bytes_total',
    'Total received bytes per device (source IP)',
    ['device']
)

gateway_transmitted_bytes_total = Counter(
    'dynamic_routing_gateway_transmitted_bytes_total',
    'Total transmitted bytes per device (destination IP)',
    ['device']
)

tested_IP_total = Counter(
    'dynamic_routing_tested_IP_total',
    'Total number of IPs tested'
)


def parse_arguments():
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description="Extracts unique IPs and ports from pcap files, checks if tcpdump is writing to them, and writes them to a database."
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to configuration file (JSON format)."
    )
    return parser.parse_args()


def read_config(config_path):
    """Reads the JSON configuration file."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"Error reading config file: {e}")
        sys.exit(1)


def is_file_being_written(filepath):
    """Checks if a file is currently being written to by tcpdump using lsof."""
    try:
        result = subprocess.run(["lsof", "-t", filepath], capture_output=True, text=True, check=True)
        # If lsof returns a process ID, the file is open
        return bool(result.stdout.strip())
    except subprocess.CalledProcessError:
        # lsof can also error if the file doesn't exist or is invalid. Consider it not being written.
        return False
    except FileNotFoundError:  # lsof not found on the system
        print("Error: lsof not found. Please install it (e.g., sudo apt install lsof). Cannot reliably check for open files.")
        sys.exit(1)  # or return False, depending on desired behavior


def extract_unique_ip_ports_with_time(filepath, local_ips):
    """Extracts unique IP addresses and their associated ports from a pcap file using scapy."""
    # check if the file name started with tun, which is the VPN
    ip_port_to_times = defaultdict(set) 
    
    try:
        packets = rdpcap(filepath)
        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[IP].sport if hasattr(packet[IP], 'sport') else None
                dst_port = packet[IP].dport if hasattr(packet[IP], 'dport') else None
                
                # Accurate packet length from IP layer
                try:
                    bytes_len = packet[IP].len  # Original packet length from pcap record
                except AttributeError:
                    print(f"Warning: Packet in {filepath} missing 'len' field in IP layer. Using captured length instead.")
                    bytes_len = len(packet)

                
                # if both src and dst IP are in the 10.8.x.x or 192.168.x.x, ignore it
                if (src_ip.startswith("10.8.") or src_ip.startswith("192.168.")) and (dst_ip.startswith("10.8.") or dst_ip.startswith("192.168.")):
                    continue

                # get the device name from the first part of file name before '-'
                device_name = os.path.basename(filepath).split('-')[0]
                if dst_ip in  local_ips:
                    gateway_received_bytes_total.labels(device=device_name).inc(bytes_len)
                elif src_ip in local_ips:
                    gateway_transmitted_bytes_total.labels(device=device_name).inc(bytes_len)

                # Extract ports if TCP or UDP layers are present
                if packet.haslayer('TCP'):
                    src_port = packet['TCP'].sport
                    dst_port = packet['TCP'].dport
                    ip_port_to_times[(src_ip, src_port)].add(float(packet.time))
                    ip_port_to_times[(dst_ip, dst_port)].add(float(packet.time))
                elif packet.haslayer('UDP'):
                    src_port = packet['UDP'].sport
                    dst_port = packet['UDP'].dport
                    ip_port_to_times[(src_ip, src_port)].add(float(packet.time))
                    ip_port_to_times[(dst_ip, dst_port)].add(float(packet.time))
                else:
                    # Non-TCP/UDP packets do not have ports; skip them
                    continue
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
    return {k: sorted(v) for k, v in ip_port_to_times.items()}


def create_ip_route_table(conn):
    """Creates the IP_ROUTE_TABLE in the database if it doesn't exist."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS IP_ROUTE_TABLE (
                    ip_address inet,
                    port integer,
                    create_time timestamp with time zone NOT NULL DEFAULT now(),
                    last_hit_time timestamp with time zone NOT NULL DEFAULT now(),
                    PRIMARY KEY (ip_address)
                );
            """)
            print("IP_ROUTE_TABLE created or already exists.")
            # Create IP_ROUTE_TEST_RESULT
            cur.execute("""
                CREATE TABLE IF NOT EXISTS IP_ROUTE_TEST_RESULT (
                    ip_address inet,
                    gateway inet,
                    rtt integer,
                    create_time timestamp with time zone NOT NULL DEFAULT now(),
                    PRIMARY KEY (ip_address, gateway),
                    FOREIGN KEY (ip_address) REFERENCES IP_ROUTE_TABLE(ip_address) ON DELETE CASCADE
                );
            """)
            print("IP_ROUTE_TEST_RESULT created or already exists.")
            conn.commit()
            return True
    except psycopg2.Error as e:
        print(f"Error creating IP_ROUTE_TABLE: {e}")
        return False

def insert_or_update_ips(conn, ip_port_to_times, local_ips, default_gateway):
    """Inserts or updates IP addresses and their ports in the database, excluding the local IP."""
    try:
        with conn.cursor() as cur:
            for (ip, port), timestamps in ip_port_to_times.items():
                if ip in local_ips:
                    continue  # Skip the local IP

                # get the maximum timestamp from timestamps
                max_timestamp = max(timestamps)
                try:
                    cur.execute("""
                        INSERT INTO IP_ROUTE_TABLE (ip_address, port, last_hit_time)
                        VALUES (%s, %s, to_timestamp(%s))
                        ON CONFLICT (ip_address) 
                            DO UPDATE SET 
                                port = EXCLUDED.port,
                                last_hit_time = GREATEST(IP_ROUTE_TABLE.last_hit_time, EXCLUDED.last_hit_time);
                    """, (ip, port, max_timestamp))
                except psycopg2.errors.InvalidTextRepresentation as e:
                    print(f"Skipping invalid IP address or port: {ip}:{port} due to: {e}")
                    continue

        conn.commit()
        print(f"Inserted/Updated {len(ip_port_to_times)} IP:Port pairs in the database.")
    except psycopg2.Error as e:
        print(f"Error inserting/updating IPs and ports in the database: {e}")
        return False
    return True




def main():
    args = parse_arguments()
    config = read_config(args.config)

    # Extract config parameters
    db_config = config.get("database", {})
    metrics_listen_port = config.get("metrics_listen_port", 8100)
    raw_file_dir = config.get("raw_file_directory", "raw_files")
    local_ips = config.get("local_ips", [])

    # Start Prometheus metrics server
    start_http_server(metrics_listen_port)
    print(f"Prometheus metrics available at http://localhost:{metrics_listen_port}/metrics")


    # Validate required config parameters
    required_db_keys = ["name", "user", "password"]
    if not all(k in db_config for k in required_db_keys):
        print("Error: Database configuration must include 'name', 'user', and 'password'.")
        sys.exit(1)

    # Database connection parameters
    db_params = {
        "dbname": db_config["name"],
        "user": db_config["user"],
        "password": db_config["password"],
        "host": db_config.get("host", "localhost"),
        "port": db_config.get("port", 5432),
    }

    try:
        conn = psycopg2.connect(**db_params)
    except psycopg2.Error as e:
        print(f"Error connecting to the database: {e}")
        sys.exit(1)

    if not create_ip_route_table(conn):
        conn.close()
        sys.exit(1)

    while True:
        # Process pcap files
        pcap_files = sorted(glob.glob(os.path.join(raw_file_dir, "*.pcap*")))  # Sort for processing order

        for filepath in pcap_files:
            if is_file_being_written(filepath):
                print(f"Skipping {filepath} - being written to by tcpdump.")
                continue
            
            # remove file with 0 size
            if os.path.getsize(filepath) == 0:
                print(f"Skipping {filepath} - file is empty.")
                #os.remove(filepath)
                continue


            print(f"Processing {filepath}")
            ip_port_to_times = extract_unique_ip_ports_with_time(filepath, local_ips)

            if ip_port_to_times:
                insert_or_update_ips(conn, ip_port_to_times, local_ips)

            # remove the file
            print(f"deleting {filepath}")
            os.remove(filepath)

        # to sleep few seconds before the next iteration
        time.sleep(waiting_interval)
        

    conn.close()
    print("Done.")


if __name__ == "__main__":
    main()