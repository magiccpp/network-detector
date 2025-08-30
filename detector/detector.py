
import asyncio
import ssl
from aiohttp import web
import json
import subprocess
import time
from typing import List, Dict, Any, Optional


async def measure_tcp_rtt(dest_ip: str, dest_port: int, timeout: float = 2.0) -> Optional[float]:
    """
    Measure the TCP RTT by attempting to establish a connection.
    For port 443, ensure that data is transferred by performing an SSL handshake
    and sending an HTTP HEAD request.
    
    Returns RTT in milliseconds or None if failed.
    """
    start_time = time.time()
    reader = writer = None
    
    try:
        if dest_port == "443":
            # Create an SSL context
            ssl_context = ssl.create_default_context()
            # ignore ssl verify
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            
            # Initiate the SSL connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(dest_ip, dest_port, ssl=ssl_context),
                timeout=timeout
            )
            
            # Send a simple HTTP HEAD request
            http_request = f"HEAD / HTTP/1.0\r\nHost: {dest_ip}\r\n\r\n"
            writer.write(http_request.encode('utf-8'))
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            
            # Wait for the response
            response = await asyncio.wait_for(reader.readline(), timeout=timeout)
            
            if not response:
                # No data received
                raise ConnectionError("No data received after sending HTTP HEAD request.")
            
        else:
            # For other ports, just establish a TCP connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(dest_ip, dest_port),
                timeout=timeout
            )
        
        end_time = time.time()
        rtt = (end_time - start_time) * 1000  # Convert to milliseconds
        return rtt

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError, ConnectionError) as e:
        print(f"Error measuring RTT to {dest_ip}:{dest_port} - {e}")
        return None
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

async def handle_test_route(request: web.Request) -> web.Response:
    """
    Handle the POST request to test routes.
    Expects JSON with keys:
    - destination_ip: str
    - destination_port: int
    """
    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON payload."}, status=400)

    # Validate input
    destination_ip = data.get('destination_ip')
    destination_port = data.get('destination_port')
    
    if not destination_ip or not destination_port:
        return web.json_response({"error": "Missing destination_ip or destination_port"}, status=400)

    try:
        # Measure RTT
        rtt = await measure_tcp_rtt(destination_ip, destination_port)

        # Prepare results
        results = {
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "rtt_ms": rtt
        }

        return web.json_response({"results": results})

    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def init_app() -> web.Application:
    app = web.Application()
    app.router.add_post('/test_route', handle_test_route)
    return app

def main():
    app = asyncio.run(init_app())
    web.run_app(app, host='0.0.0.0', port=8080)

if __name__ == "__main__":
    main()