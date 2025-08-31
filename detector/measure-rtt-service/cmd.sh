# the command for testing the service
curl -X POST http://localhost:8080/test_route \
     -H "Content-Type: application/json" \
     -d '{"destination_ip": "59.82.43.234", "destination_port": "443"}'

# important IP
# China DNS: 116.228.111.118
# blingo:
# 47.246.20.175


# start up capturing traffic