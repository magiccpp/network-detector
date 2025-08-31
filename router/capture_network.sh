#!/bin/bash

# Directory to store the capture files
CAPTURE_DIR="/var/logs/router_raw_files"

# Ensure the capture directory exists
mkdir -p "$CAPTURE_DIR"
chmod 777 "$CAPTURE_DIR"
# Start tcpdump for tun0 interface
nohup sudo tcpdump tcp -i tun0 -n -q -l -C 1 -s 100 -G 60 -w "$CAPTURE_DIR/tun0-%Y%m%d-%H%M%S.pcap" &
TUN0_PID=$!

# Start tcpdump for eth0 interface, excluding port 1395
nohup sudo tcpdump -i eth0 not port 1395 -n -q -l -C 1 -s 100 -G 60 -w "$CAPTURE_DIR/eth0-%Y%m%d-%H%M%S.pcap" &
ETH0_PID=$!

nohup sudo tcpdump -i eth1 'udp dst port 53 and (udp[10] & 0x80) = 0' -n -q -l -C 1 -G 60 -w "$CAPTURE_DIR/eth1-dns-%Y%m%d-%H%M%S.pcap" &
ETH1_PID=$!

echo "Started tcpdump on tun0 with PID $TUN0_PID"
echo "Started tcpdump on eth0 with PID $ETH0_PID"
echo "Started tcpdump on eth1 with PID $ETH1_PID"

# Function to clean up files older than 60 minutes
cleanup_old_files() {
    find "$CAPTURE_DIR" -type f -name "*.pcap" -mmin +60 -exec rm -f {} \;
}

# Run the cleanup in the background
(
    while true; do
        cleanup_old_files
        sleep 300 # Wait for 5 minutes before next cleanup
    done
) &

CLEANUP_PID=$!

echo "Started cleanup process with PID $CLEANUP_PID"

# Optional: Trap script termination to kill background processes gracefully
trap "echo 'Stopping tcpdump and cleanup processes...'; kill $TUN0_PID $ETH0_PID $ETH1_PID $CLEANUP_PID; exit" SIGINT SIGTERM

# Keep the script running to maintain background processes
wait


