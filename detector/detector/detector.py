import argparse
from collections import defaultdict
import sys
from datetime import datetime, timezone
import time
import json
import psycopg2
import asyncio
import aiohttp

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
                    gateway_name varchar(50),
                    rtt integer,
                    create_time timestamp with time zone NOT NULL DEFAULT now(),
                    PRIMARY KEY (ip_address, gateway_name),
                    FOREIGN KEY (ip_address) REFERENCES IP_ROUTE_TABLE(ip_address) ON DELETE CASCADE
                );
            """)
            print("IP_ROUTE_TEST_RESULT created or already exists.")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS DOMAIN_NAME_TABLE (
                    domain_name varchar(253),
                    create_time timestamp with time zone NOT NULL DEFAULT now(),
                    last_hit_time timestamp with time zone NOT NULL DEFAULT now(),
                    PRIMARY KEY (domain_name)
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_ip_route_last_hit_time ON IP_ROUTE_TABLE (last_hit_time);
            """)
            
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_test_result_ip_time
                        ON IP_ROUTE_TEST_RESULT (ip_address, create_time DESC);
            """)
            
            conn.commit()
            return True
    except psycopg2.Error as e:
        print(f"Error creating IP_ROUTE_TABLE: {e}")
        return False

def select_ips_to_test(conn, recent_ip_window_hours, test_result_stale_hours, max_results=8):
    """Selects up to `max_results` most recently hit IPs that need gateway testing."""
    try:
        with conn.cursor() as cur:
            query = """
                WITH latest_test AS (
                    SELECT ip_address, MAX(create_time) AS last_test_time
                    FROM IP_ROUTE_TEST_RESULT
                    GROUP BY ip_address
                )
                SELECT ip.ip_address, ip.port
                FROM IP_ROUTE_TABLE AS ip
                LEFT JOIN latest_test AS t USING (ip_address)
                WHERE ip.last_hit_time >= NOW() - make_interval(hours => %s)
                  AND (
                        t.last_test_time IS NULL
                        OR t.last_test_time < NOW() - make_interval(hours => %s)
                      )
                ORDER BY ip.last_hit_time DESC
                LIMIT %s;
            """
            cur.execute(query, (recent_ip_window_hours, test_result_stale_hours, max_results))
            results = cur.fetchall()
            return [r for r in results]
    except psycopg2.Error as e:
        print(f"Error selecting IPs to test: {e}")
        return []

async def test_ips_via_gateways_async(conn, ips, gateways):
    """Test all IPs via all gateways concurrently and store results."""
    timeout = aiohttp.ClientTimeout(total=10)
    connector = aiohttp.TCPConnector(limit=100)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        tasks = []
        for ip_addr, dest_port in ips:
            for gw in gateways:
                gw_ip = gw["measure_rtt_service_ip"]
                gw_port = int(gw["measure_rtt_service_port"])
                gw_name = gw["name"]
                tasks.append(_run_one_test(session, conn, ip_addr, dest_port, gw_name, gw_ip, gw_port))
        await asyncio.gather(*tasks, return_exceptions=True)

def insert_test_result(conn, ip_addr: str, gw_name: str, rtt_ms: int):
    """Upsert a test result row."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO IP_ROUTE_TEST_RESULT (ip_address, gateway_name, rtt)
                VALUES (%s, %s, %s)
                ON CONFLICT (ip_address, gateway_name)
                DO UPDATE SET
                    rtt = EXCLUDED.rtt,
                    create_time = now();
            """, (ip_addr, gw_name, int(rtt_ms)))
        conn.commit()
        print(f"Saved test result: ip={ip_addr} via gateway={gw_name} rtt={rtt_ms}ms")
    except Exception as e:
        conn.rollback()
        print(f"Failed to save test result for {ip_addr} via {gw_name}: {e}")

async def _post_test(session, dest_ip: str, dest_port: int, gw_ip: str, gw_port: int):
    """POST to the gateway's /test_route and return RTT in ms if found."""
    url = f"http://{gw_ip}:{gw_port}/test_route"
    payload = {"destination_ip": dest_ip, "destination_port": dest_port}
    try:
        async with session.post(url, json=payload) as resp:
            text = await resp.text()
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status}: {text[:200]}")
            # be tolerant about content-type
            try:
                data = await resp.json(content_type=None)
            except Exception:
                data = json.loads(text)
            print(f"Gateway test response for {dest_ip} from {url}: {data}")
            # Sometimes nested, e.g., {"result":{"rtt_ms":12}}
            if isinstance(data, dict) and isinstance(data.get("results"), dict):
                if "rtt_ms" in data["results"]:
                    rtt = data["results"]["rtt_ms"]
                    if rtt is None:
                        return -1
                    else:
                        return int(rtt)
            print(f"No RTT field in response for {dest_ip} from {url}: {data}")
    except Exception as e:
        print(f"Gateway test error {gw_ip}:{gw_port} -> {dest_ip}: {e}")
    return None


async def _run_one_test(session, conn, ip_addr, dest_port, gw_name, gw_ip, gw_port):
    rtt = await _post_test(session, ip_addr, dest_port, gw_ip, gw_port)
    if rtt is not None:
        insert_test_result(conn, ip_addr, gw_name, int(round(rtt)))




def main():
    args = parse_arguments()
    config = read_config(args.config)
    db_config = config.get("database", {})
    waiting_time_interval = config.get("waiting_time_interval", 5)
    recent_ip_window_hours = config.get("recent_ip_window_hours", 1)
    test_result_stale_hours = config.get("test_result_stale_hours", 7)

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
        # Select and process IPs that need gateway testing
        ips_to_test = select_ips_to_test(conn, recent_ip_window_hours, test_result_stale_hours)
        print("ips_to_test", ips_to_test)
        if ips_to_test:
            print(f"Testing gateways for {len(ips_to_test)} IPs.")
            gateways = config.get("gateways_to_mesure", [])
        
            asyncio.run(test_ips_via_gateways_async(conn, ips_to_test, gateways))


        # to sleep few seconds before the next iteration
        time.sleep(waiting_time_interval)



if __name__ == "__main__":
    main()
