#!/bin/bash

# Start OpenVPN in the background
openvpn --config /etc/openvpn/openvpn.ovpn &

# Wait for OpenVPN to establish connection
sleep 10

# Run the Python application
python /app/detector.py