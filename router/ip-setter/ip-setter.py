
import argparse
import os
import sys
import json
import psycopg2
import subprocess
import time

def read_config(config_path):
    """Reads the JSON configuration file."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"Error reading config file: {e}")
        sys.exit(1)

# the action can be add or delete
def append_to_ipset_entry(ip: str, set_name: str) -> bool:
    """
    Check if an IP exists in an ipset. If it does not, add it.

    Parameters:
    - ip (str): The IP address to check/add.
    - set_name (str): The name of the ipset.

    Returns:
    - bool: True if the IP exists or was successfully added, False otherwise.
    """
    try:
        # First, check if the IP exists in the ipset
        check_cmd = ['ipset', 'test', set_name, ip]
        result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode == 0:
            # IP exists in the ipset
            print(f"IP {ip} already exists in ipset '{set_name}'.")
            return True
        else:
            # IP does not exist, attempt to add it
            add_cmd = ['ipset', 'add', set_name, ip]
            add_result = subprocess.run(add_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if add_result.returncode == 0:
                # Successfully added the IP
                print(f"IP {ip} added to ipset '{set_name}'.")
                return True
            else:
                # Failed to add the IP
                return False
    except FileNotFoundError:
        # ipset command not found
        print("Error: ipset command not found.")
        return False
    except Exception as e:
        # Handle other unforeseen exceptions
        print(f"An unexpected error occurred: {e}")
        return False


# the action can be add or delete
def remove_from_ipset_entry(ip: str, set_name: str) -> bool:
    """
    Check if an IP exists in an ipset. If it does not, add it.

    Parameters:
    - ip (str): The IP address to check/add.
    - set_name (str): The name of the ipset.

    Returns:
    - bool: True if the IP exists or was successfully added, False otherwise.
    """
    try:
        # First, check if the IP exists in the ipset
        check_cmd = ['ipset', 'test', set_name, ip]
        result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode != 0:
            # IP exists in the ipset
            print(f"IP {ip} does not exists in ipset '{set_name}'.")
            return True
        else:
            # IP does exist, attempt to remove it
            del_cmd = ['ipset', 'del', set_name, ip]
            del_result = subprocess.run(del_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if del_result.returncode == 0:
                # Successfully added the IP
                print(f"IP {ip} deleted from ipset '{set_name}'.")
                return True
            else:
                # Failed to remove the IP
                return False
    except FileNotFoundError:
        # ipset command not found
        print("Error: ipset command not found.")
        return False
    except Exception as e:
        # Handle other unforeseen exceptions
        print(f"An unexpected error occurred: {e}")
        return False

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

def print_latest_gateway_results_per_ip(conn, default_gateway_name):
    """
    Fetch rows grouped by IP and gateway (keep the latest per gateway in Python),
    then print per IP: [[gateway_name, rtt], ...]
    """
    
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    ip_address::text AS ip_address,
                    gateway_name,
                    rtt,
                    create_time
                FROM IP_ROUTE_TEST_RESULT
                ORDER BY ip_address, gateway_name, create_time DESC;
            """)
            rows = cur.fetchall()

        
        
        # data = { ip: { gateway_name: (rtt, create_time) } }
        data = {}
        for ip, gw, rtt, ts in rows:
            ip_entry = data.setdefault(ip, {})
            # first occurrence per (ip, gw) is the latest because of ORDER BY ... DESC
            if gw not in ip_entry:
                ip_entry[gw] = (rtt, ts)

            
        # Print in the requested wide-ish format
        for ip, gw_map in data.items():
            # Go through gw_map, if a gw is not default gateway, but its RTT is less than the default gateway's RTT by 30%, then we print out something, 
            threshold_rtt = None
            if default_gateway_name in gw_map:
                default_rtt = gw_map[default_gateway_name][0]
                if default_rtt == -1:
                    default_rtt = 2000
                if default_rtt is not None and default_rtt > 0:
                    threshold_rtt = default_rtt * 0.7
            if threshold_rtt is None:
                print(f"skip {ip}")
                continue
            
            minRtt=999999
            min_gw_name = None
            for gw, (rtt, _) in gw_map.items():
                if gw == default_gateway_name or rtt is None or rtt < 0:
                    continue
                minRtt = min(minRtt, rtt)
                min_gw_name = gw
            
            if min_gw_name is not None and minRtt < threshold_rtt:
                print(f"ip: {ip}, threshold_rtt {threshold_rtt}, minRtt: {minRtt}, min_gw_name: {min_gw_name}")
                if append_to_ipset_entry(ip, "bypass_vpn"):
                    # update the database to set the column current_gateway to the alternative gateway
                    with conn.cursor() as cur:
                        cur.execute("""
                            UPDATE IP_CURRENT_GATEWAY_TABLE
                            SET gateway_name = %s
                            WHERE ip_address = %s
                        """, (min_gw_name, ip))
                        conn.commit()
                        print(f"IP {ip} is appended into ipset.")
                else:
                    print(f"Failed to add IP {ip} to ipset 'bypass_vpn'.")

        return data  # in case you also want to use it programmatically

    except Exception as e:
        print(f"Error fetching/printing latest gateway results: {e}")
        return {}

def create_ip_set_table(conn):
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS IP_CURRENT_GATEWAY_TABLE (
                    ip_address inet,
                    gateway_name varchar(50),
                    create_time timestamp with time zone NOT NULL DEFAULT now(),
                    PRIMARY KEY (ip_address)
                );
            """)
            conn.commit()
            return True
    except psycopg2.Error as e:
        print(f"Error creating IP_ROUTE_TABLE: {e}")
        return False

def main():
    print("Starting the IP set management script...")
    args = parse_arguments()
    
    if not args.config:
        print("Error: Configuration file path is required.")
        sys.exit(1)

    if not os.path.exists(args.config):
        print(f"Error: Configuration file '{args.config}' does not exist.")
        sys.exit(1)




    config = read_config(args.config)

    # Extract config parameters
    db_config = config.get("database", {})
    default_gateway = config.get("default_gateway", "10.8.0.1")
    alternative_gateway = config.get("alternative_gateway", "192.168.71.1")
    waiting_interval = config.get("waiting_interval", 5)
    update_route_threshold = config.get("update_route_threshold", 1.4)
    route_stale_hours = config.get("route_stale_hours", 72)

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
        
    if not create_ip_set_table(conn):
        conn.close()
        sys.exit(1)
        
    gateways = config.get("gateways_to_mesure", [])
    print(gateways)
    default_gateway_name = None
    for gateway in gateways:
        if gateway.get("default", False):
            default_gateway_name = gateway.get("name")
    # exit if default_gateway_name is None
    if default_gateway_name is None:
        print("Error: No default gateway found.")
        sys.exit(1)

    # enumerate lines from the table ip_route_table, find out those rows:
    # the column default_gateway_rtt is larger than alternative_gateway_rtt and the current_gateway is the default gateway

    while True:
        # Find out the ip routes that haven't been seen more than route_stale_hours
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip_address
            FROM ip_route_table WHERE
            (last_hit_time IS NULL OR last_hit_time < (NOW() - INTERVAL '%s hours'))
        """, (route_stale_hours,))
        rows = cursor.fetchall()
        # in the case the current_gateway is not the default gateway, we must delete it from the ipset
        if rows:
            print("IPs that are staled:", len(rows))
            for row in rows:
                ip = row[0]
                # delete the IP set if it is in the ipset
                if remove_from_ipset_entry(ip, "bypass_vpn"):
                    print(f"IP {ip} removed from ipset 'bypass_vpn'.")


        print_latest_gateway_results_per_ip(conn, default_gateway_name)
        cursor.close()
        # to sleep few seconds before the next iteration
        time.sleep(waiting_interval)


if __name__ == "__main__":
    main()


