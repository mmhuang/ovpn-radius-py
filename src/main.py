import os
import sys
import json
import logging
import subprocess
import random
import sqlite3
import binascii
import socket
import time
import glob
import datetime
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet
import traceback

CONFIG_PATH = "/etc/openvpn/plugin/auth-radius-py/config.json"
# CONFIG_PATH = "/var/huabo/workspace/openvpn/src/plugins/auth-radius-py/config.json"
DATABASE_PATH = "/etc/openvpn/plugin/auth-radius-py/ovpn-radius.db"
DICTIONARY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dictionary")

# --- Config loading ---
def load_config():
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

config = load_config()

# --- Logging setup ---
log_file = config.get("LogFile")
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# --- Database ---
def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    # Create the new ovpn_session table with bandwidth tracking (removed session_duration)
    c.execute("""
        CREATE TABLE IF NOT EXISTS ovpn_session(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL UNIQUE,
            user_name TEXT NOT NULL,
            user_ip TEXT NOT NULL,
            user_port TEXT NOT NULL,
            nas_name TEXT NOT NULL,
            nas_ip TEXT NOT NULL,
            nas_port TEXT NOT NULL,
            bytes_sent INTEGER DEFAULT 0,
            bytes_received INTEGER DEFAULT 0,
            start_time TIMESTAMP NOT NULL,
            update_time TIMESTAMP NOT NULL
        );
    """)
    conn.commit()
    return conn

# Session management functions
def create_session(conn, username, user_ip, user_port, nas_name, nas_ip, nas_port, daemon_pid=""):
    """Create a new session record"""
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Get next ID using sqlite_sequence table
    c = conn.cursor()
    c.execute("SELECT seq FROM sqlite_sequence WHERE name='ovpn_session'")
    result = c.fetchone()
    
    # If no result, it means no rows have been inserted yet, so next_id would be 1
    # Otherwise, seq+1 will be the next ID that will be assigned
    next_id = 1 if result is None else result[0] + 1

    # Create session_id in the format: {nas_ip}-{nas_port}-{daemon_pid}-{id}
    session_id = f"{nas_ip}-{nas_port}-{daemon_pid}-{next_id}"
    
    # Insert new session
    c.execute("""
        INSERT INTO ovpn_session(session_id, user_name, user_ip, user_port, 
                               nas_name, nas_ip, nas_port, start_time, update_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (session_id, username, user_ip, user_port, nas_name, nas_ip, nas_port, current_time, current_time))
    conn.commit()
    
    logging.info(f"create_session: Created new session {session_id} for user {username}")
    return session_id

def update_session(conn, session_id, bytes_sent=0, bytes_received=0):
    """Update an existing session's update_time and bandwidth statistics"""
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    c = conn.cursor()
    c.execute("""
        UPDATE ovpn_session 
        SET update_time = ?, bytes_sent = ?, bytes_received = ?
        WHERE session_id = ?
    """, (current_time, bytes_sent, bytes_received, session_id))
    
    if c.rowcount == 0:
        logging.warning(f"update_session: Session {session_id} not found for update")
        return False
    
    conn.commit()
    logging.info(f"update_session: Updated session {session_id} with bytes_sent={bytes_sent}, bytes_received={bytes_received}")
    return True

def delete_session(conn, session_id):
    """Delete a session"""
    c = conn.cursor()
    c.execute("DELETE FROM ovpn_session WHERE session_id = ?", (session_id,))
    if c.rowcount == 0:
        logging.warning(f"delete_session: Session {session_id} not found for deletion")
        return False
    
    conn.commit()
    logging.info(f"delete_session: Deleted session {session_id}")
    return True

def get_session_id(conn, username, user_ip, user_port, nas_ip, nas_port):
    """Find an existing session record"""
    c = conn.cursor()
    # sql_debug = f"""SELECT session_id FROM ovpn_session 
    #     WHERE user_name = '{username}' AND user_ip = '{user_ip}' AND user_port = '{user_port}' 
    #     AND nas_ip = '{nas_ip}' AND nas_port = '{nas_port}'"""
    # logging.info(f"get_session: Executing SQL: {sql_debug}")
    c.execute("""
        SELECT session_id FROM ovpn_session 
        WHERE user_name = ? AND user_ip = ? AND user_port = ? AND nas_ip = ? AND nas_port = ?
    """, (username, user_ip, user_port, nas_ip, nas_port))
    
    result = c.fetchone()
    if result:
        return result[0]
    return None

def get_session_detail_by_id(conn, session_id):
    """Get session details by session_id"""
    c = conn.cursor()
    c.execute("SELECT * FROM ovpn_session WHERE session_id = ?", (session_id,))
    
    result = c.fetchone()
    if result:
        # Fixed indices to match the actual database schema
        return {
            "id": result[0],              # ID is at index 0
            "session_id": result[1],      # session_id is at index 1
            "user_name": result[2],       # user_name is at index 2
            "user_ip": result[3],         # user_ip is at index 3
            "user_port": result[4],       # user_port is at index 4
            "nas_name": result[5],        # nas_name is at index 5
            "nas_ip": result[6],          # nas_ip is at index 6
            "nas_port": result[7],        # nas_port is at index 7
            "bytes_sent": result[8],      # bytes_sent is at index 8
            "bytes_received": result[9],  # bytes_received is at index 9
            "start_time": result[10],     # start_time is at index 10
            "update_time": result[11]     # update_time is at index 11
        }
    return None

# --- Helper functions ---
def load_radius_dictionaries():
    """Load all dictionary files from the dictionary directory"""
    dictionary_files = glob.glob(os.path.join(DICTIONARY_PATH, "dictionary.*"))
    
    if not dictionary_files:
        logging.error(f"No dictionary files found in {DICTIONARY_PATH}")
        return None
    
    logging.info(f"Loading {len(dictionary_files)} RADIUS dictionary files")
    
    # Create a base dictionary
    combined_dict = Dictionary()
    
    # Load each dictionary file
    for dict_file in dictionary_files:
        try:
            logging.info(f"Loading dictionary file: {dict_file}")
            combined_dict.ReadDictionary(dict_file)
        except Exception as e:
            logging.warning(f"Failed to load dictionary file {dict_file}: {e}")
    
    return combined_dict

def retry_radius_request(func, *args, **kwargs):
    """Retry a radius request function with configured retry parameters"""
    retry_count = config['Radius']['Retry']['Count']
    retry_interval = config['Radius']['Retry']['Interval']
    
    last_exception = None
    for attempt in range(retry_count):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            last_exception = e
            if attempt < retry_count - 1:  # Don't log "retrying" on the last attempt
                logging.warning(f"RADIUS request failed (attempt {attempt+1}/{retry_count}): {e}. Retrying in {retry_interval} seconds...")
                time.sleep(retry_interval)
            else:
                logging.error(f"RADIUS request failed after {retry_count} attempts. Last error: {e}")
    
    # If we get here, all retries failed
    if last_exception:
        raise last_exception
    else:
        raise Exception("All retry attempts failed with unknown error")

def is_valid_utf8_from_hex(hexa_string):
    try:
        number_str = hexa_string.lower().replace("0x", "")
        decoded = binascii.unhexlify(number_str)
        return decoded.decode("utf-8")
    except Exception as e:
        logging.error(f"is_valid_utf8_from_hex: failed with {e}")
        sys.exit(50)

def get_environment():
    printenv = "/usr/bin/printenv"
    logging.info(f"getEnvironment: executing {printenv}")
    try:
        output = subprocess.check_output([printenv], text=True)
        for line in output.splitlines():
            if "password" not in line.lower() and line:
                logging.info(f"getEnvironment: {line}")
        logging.info(f"getEnvironment: finished. {printenv}")
        sys.exit(0)
    except Exception as e:
        logging.error(f"getEnvironment: failed with {e}")
        sys.exit(20)

def write_ccd_config(username, attributes):
    """Write client-specific configuration to CCD directory based on RADIUS attributes"""
    ccd_dir = config['ServerInfo'].get('CCD', '/etc/openvpn/ccd')
    if not os.path.exists(ccd_dir):
        try:
            os.makedirs(ccd_dir, exist_ok=True)
            logging.info(f"write_ccd_config: Created CCD directory: {ccd_dir}")
        except Exception as e:
            logging.error(f"write_ccd_config: Failed to create CCD directory: {e}")
            return False
            
    ccd_file = os.path.join(ccd_dir, username)
    try:
        with open(ccd_file, 'w') as f:
            logging.info(f"write_ccd_config: Writing configuration for user {username}")
            
            # Process Framed-IP-Address and Framed-IP-Netmask
            if 'Framed-IP-Address' in attributes:
                ip_address = attributes['Framed-IP-Address'][0]
                netmask = attributes.get('Framed-IP-Netmask', [None])[0]
                
                if ip_address:
                    if netmask:
                        f.write(f"ifconfig-push {ip_address} {netmask}\n")
                        logging.info(f"write_ccd_config: Added ifconfig-push {ip_address} {netmask}")
                    else:
                        # If no netmask provided, use default
                        f.write(f"ifconfig-push {ip_address} 255.255.255.0\n")
                        logging.info(f"write_ccd_config: Added ifconfig-push {ip_address} 255.255.255.0 (default netmask)")
            
            # Process DNS servers (Microsoft vendor-specific attributes)
            if 'MS-Primary-DNS-Server' in attributes:
                primary_dns = attributes['MS-Primary-DNS-Server'][0]
                f.write(f"push \"dhcp-option DNS {primary_dns}\"\n")
                logging.info(f"write_ccd_config: Added primary DNS server: {primary_dns}")
                
            if 'MS-Secondary-DNS-Server' in attributes:
                secondary_dns = attributes['MS-Secondary-DNS-Server'][0]
                f.write(f"push \"dhcp-option DNS {secondary_dns}\"\n")
                logging.info(f"write_ccd_config: Added secondary DNS server: {secondary_dns}")
            
            # Process Framed-IP-Routes
            if 'Framed-Route' in attributes:
                for route in attributes['Framed-Route']:
                    f.write(f"push \"route {route}\"\n")
                    logging.info(f"write_ccd_config: Added route {route}")
            
            # Process Framed-IPv6-Routes
            if 'Framed-IPv6-Route' in attributes:
                for route in attributes['Framed-IPv6-Route']:
                    f.write(f"push \"route-ipv6 {route}\"\n")
                    logging.info(f"write_ccd_config: Added IPv6 route {route}")
            
            # Add other attributes that might be useful for OpenVPN configuration
            if 'Session-Timeout' in attributes:
                timeout = attributes['Session-Timeout'][0]
                f.write(f"push \"auth-token-lifetime {timeout}\"\n")
                logging.info(f"write_ccd_config: Set session timeout to {timeout} seconds")
                
            if 'Acct-Interim-Interval' in attributes:
                interval = attributes['Acct-Interim-Interval'][0]
                f.write(f"# RADIUS specified interim interval: {interval} seconds\n")
                logging.info(f"write_ccd_config: Noted interim interval of {interval} seconds")
                
        return True
    except Exception as e:
        logging.error(f"write_ccd_config: Failed to write CCD file for {username}: {e}")
        return False

def log_radius_reply(reply, prefix=""):
    """Log RADIUS reply attributes in a readable format for debugging"""
    logging.info(f"{prefix}RADIUS Reply Code: {reply.code}")
    logging.info(f"{prefix}RADIUS Reply Attributes:")
    
    for attr_name in reply.keys():
        values = reply[attr_name]
        for value in values:
            # Format binary data for better readability
            if isinstance(value, bytes):
                try:
                    # Try to decode as ASCII if possible
                    decoded = value.decode('ascii', errors='replace')
                    logging.info(f"{prefix}  {attr_name}: {decoded} (hex: {value.hex()})")
                except:
                    logging.info(f"{prefix}  {attr_name}: (binary) {value.hex()}")
            else:
                logging.info(f"{prefix}  {attr_name}: {value}")

def accounting_request(request_type, conn):
    logging.info(f"accountingRequest: prepare send request to {config['Radius']['Accounting']['Server']} with request type: {request_type}")
    
    # Get environment variables for session details
    username = os.environ.get('common_name', os.environ.get('username', ''))
    user_ip = os.environ.get('untrusted_ip', '')
    user_port = os.environ.get('trusted_port', '')
    nas_name = config['ServerInfo']['Identifier']
    nas_ip = os.environ.get('local_1', config['ServerInfo']['IpAddress'])
    nas_port = os.environ.get('local_port_1', '1194')
    user_assigned_ip = os.environ.get('ifconfig_pool_remote_ip', '')
    daemon_pid = os.environ.get('daemon_pid', '')
    
    # Format station IDs according to the required format: {IP}[{PORT}]
    calling_station_id = f"{user_ip}[{user_port}]"
    called_station_id = f"{nas_ip}[{nas_port}]"

    
    logging.info(f"accountingRequest: Client info - User:{username}, IP:{user_ip}, Port:{user_port}")
    logging.info(f"accountingRequest: Server info - Name:{nas_name}, IP:{nas_ip}, Port:{nas_port}")
    
    # For update and stop requests, get traffic statistics
    bytes_sent = 0
    bytes_received = 0
    session_duration = 0  # Still needed for RADIUS but not for DB
    
    
    # Handle session based on request type
    session_id = None
    
    if request_type == "start":
        # Create a new session for start requests
        session_id = create_session(conn, username, user_ip, user_port, nas_name, nas_ip, nas_port, daemon_pid)
    else:
        if request_type in ["update", "stop"]:
            bytes_sent = int(os.environ.get('bytes_sent', '0')) if os.environ.get('bytes_sent', '').isdigit() else 0
            bytes_received = int(os.environ.get('bytes_received', '0')) if os.environ.get('bytes_received', '').isdigit() else 0
        
        # Try to find existing session for update/stop requests
        session_id = get_session_id(conn, username, user_ip, user_port, nas_ip, nas_port)
        if not session_id:
            logging.warning(f"accountingRequest: Session not found for {username} ({user_ip}:{user_port})")
            # Create a session if it doesn't exist (recovery mechanism)
            if request_type == "update":
                session_id = create_session(conn, username, user_ip, user_port, nas_name, nas_ip, nas_port, daemon_pid)
            else:
                logging.error(f"accountingRequest: Cannot process 'stop' for non-existent session")
                sys.exit(61)
        else:
            session_details = get_session_detail_by_id(conn, session_id)
            if session_details:
                session_duration = (datetime.datetime.now() - datetime.datetime.strptime(session_details['start_time'], '%Y-%m-%d %H:%M:%S')).total_seconds()

        logging.info(f"accountingRequest: Session stats - Sent: {bytes_sent} bytes, Received: {bytes_received} bytes, Duration: {session_duration}s")

    
    acct_status_type_map = {
        "start": 1,  # Start
        "update": 3, # Interim-Update
        "stop": 2    # Stop
    }
    
    acct_status_type = acct_status_type_map.get(request_type)
    if not acct_status_type:
        logging.error(f"accountingRequest: '{request_type}' request type is unknown.")
        sys.exit(61)
    
    try:

        if request_type == "stop":
            # Delete the session when stopping
            delete_session(conn, session_id)
        elif request_type == "update":
            update_session(conn, session_id, bytes_sent, bytes_received)

        srv = config['Radius']['Accounting']['Server'].split(':')
        server = srv[0]
        port = int(srv[1]) if len(srv) > 1 else 1813
        
        # Check if dictionary path exists
        if not os.path.exists(DICTIONARY_PATH):
            logging.error(f"accountingRequest: RADIUS dictionary path not found at {DICTIONARY_PATH}")
            sys.exit(63)
            
        # Load all dictionary files
        radius_dict = load_radius_dictionaries()
        if not radius_dict:
            logging.error(f"accountingRequest: Failed to load RADIUS dictionaries")
            sys.exit(63)
        
        logging.info(f"accountingRequest: Using RADIUS dictionaries from {DICTIONARY_PATH}")
        
        # Initialize RADIUS client with combined dictionary
        radius_client = Client(
            server=server,
            acctport=port,
            secret=config['Radius']['Accounting']['Secret'].encode(),
            dict=radius_dict
        )
        
        # Create accounting request
        req = radius_client.CreateAcctPacket()
        
        # Add attributes
        req["Acct-Session-Id"] = session_id
        req["Acct-Status-Type"] = acct_status_type
        req["User-Name"] = username
        
        # Add Service-Type and Framed-Protocol as requested
        req["Service-Type"] = "Outbound-User"  # Service-Type 8 for Outbound-User
        req["Framed-Protocol"] = "PPP"  # Framed-Protocol 1 for PPP
        
        # Add enhanced station identification with the required format
        req["Calling-Station-Id"] = calling_station_id
        req["Called-Station-Id"] = called_station_id
        
        # Add NAS identification attributes
        req["NAS-Identifier"] = nas_name
        req["NAS-Port-Type"] = config['ServerInfo']['PortType']
        req["NAS-Port"] = nas_port
        req["NAS-IP-Address"] = nas_ip
        req["Framed-IP-Address"] = user_assigned_ip
        
        if request_type == "stop":
            req["Acct-Terminate-Cause"] = 1  # User-Request
            # Use the values we already retrieved above
            req["Acct-Input-Octets"] = bytes_sent
            req["Acct-Output-Octets"] = bytes_received
            req["Acct-Session-Time"] = session_duration
        elif request_type == "update":
            req["Acct-Input-Octets"] = bytes_sent
            req["Acct-Output-Octets"] = bytes_received
            req["Acct-Session-Time"] = session_duration            
        
        # Send request with retry mechanism
        def send_acct_request():
            reply = radius_client.SendPacket(req)
            if reply.code != pyrad.packet.AccountingResponse:
                raise Exception("No Accounting-Response received")
            return reply
        
        reply = retry_radius_request(send_acct_request)
        
        # Log RADIUS reply in a readable format
        log_radius_reply(reply, "accountingRequest: ")
        
        logging.info(f"accountingRequest: received Accounting-Response from {config['Radius']['Accounting']['Server']}")

    except Exception as e:
        trace_msg = traceback.format_exc()
        logging.error(f"accountingRequest: Error: {trace_msg}")
        sys.exit(62)
    
    sys.exit(0)

def authenticate_user(conn):
    if len(sys.argv) <= 2:
        logging.error("authenticate: 'null' file path.")
        sys.exit(30)
    auth_file_path = sys.argv[2]
    logging.info(f"authenticate: Authentication using filepath: {auth_file_path}")
    try:
        with open(auth_file_path, "r") as f:
            lines = f.read().splitlines()
        username = lines[0] if len(lines) > 0 else ""
        password = lines[1] if len(lines) > 1 else ""
    except Exception as e:
        logging.error(f"authenticate: failed with {e}")
        sys.exit(31)
    if not username or not password:
        logging.error("authenticate: unable to authenticate username or password is null")
        sys.exit(33)
    
    logging.info(f"authenticate: trying to authenticate to {config['Radius']['Authentication']['Server']}")
    
    # Create RADIUS client using pyrad
    try:
        srv = config['Radius']['Authentication']['Server'].split(':')
        server = srv[0]
        port = int(srv[1]) if len(srv) > 1 else 1812
        
        # Check if dictionary path exists
        if not os.path.exists(DICTIONARY_PATH):
            logging.error(f"authenticate: RADIUS dictionary path not found at {DICTIONARY_PATH}")
            sys.exit(35)
        
        # Load all dictionary files
        radius_dict = load_radius_dictionaries()
        if not radius_dict:
            logging.error(f"authenticate: Failed to load RADIUS dictionaries")
            sys.exit(35)
        
        logging.info(f"authenticate: Using RADIUS dictionaries from {DICTIONARY_PATH}")
        
        # Initialize RADIUS client with combined dictionary
        client = Client(
            server=server,
            authport=port,
            secret=config['Radius']['Authentication']['Secret'].encode(),
            dict=radius_dict
        )
        
        # Create authentication request
        req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest)
        
        # Add attributes
        req["User-Name"] = username
        req["User-Password"] = req.PwCrypt(password)
        req["NAS-Identifier"] = config['ServerInfo']['Identifier']
        req["NAS-Port-Type"] = config['ServerInfo']['PortType']
        req["NAS-IP-Address"] = config['ServerInfo']['IpAddress']
        req["Service-Type"] = config['ServerInfo']['ServiceType']
        req["Framed-Protocol"] = "PPP"
        
        # Send request with retry mechanism
        def send_auth_request():
            reply = client.SendPacket(req)
            if reply.code == pyrad.packet.AccessReject:
                raise Exception("Authentication failed, user not accepted")
            elif reply.code == pyrad.packet.AccessAccept:
                return reply
            else:
                raise Exception("Authentication failed, user not accepted")
        
        reply = retry_radius_request(send_auth_request)
        
        # Log RADIUS reply in a readable format
        log_radius_reply(reply, "authenticate: ")
        
        # # Get Class attribute if present
        # class_name = ""
        # if "Class" in reply:
        #     class_data = reply["Class"][0]
        #     if isinstance(class_data, bytes):
        #         class_name = "0x" + class_data.hex()
        
        # logging.info(f"authenticate: user '{username}' with class '{class_name}' is authenticated successfully")
        
        # Check for session configuration attributes and write to CCD if present
        has_ccd_attributes = False
        ccd_attributes = {}
        
        # Collect relevant attributes for CCD
        for attr_name in reply.keys():
            if attr_name in ['Framed-IP-Address', 'Framed-IP-Netmask', 'Framed-Route', 
                            'Framed-IPv6-Route', 'Session-Timeout', 'Acct-Interim-Interval',
                            'MS-Primary-DNS-Server', 'MS-Secondary-DNS-Server']:
                has_ccd_attributes = True
                ccd_attributes[attr_name] = reply[attr_name]
                logging.info(f"authenticate: Found RADIUS attribute {attr_name}: {reply[attr_name]}")
        
        # Write CCD configuration if attributes are present
        if has_ccd_attributes:
            if write_ccd_config(username, ccd_attributes):
                logging.info(f"authenticate: CCD configuration for user '{username}' created successfully")
            else:
                logging.warning(f"authenticate: Failed to create CCD configuration for user '{username}'")
        
    except Exception as e:
        trace_msg = traceback.format_exc()
        logging.error(f"authenticate: Error: {trace_msg}")
        sys.exit(34)
    
    sys.exit(0)

def main():
    import getpass
    try:
        username = getpass.getuser()
        logging.info(f"main: running with username {username}")
    except Exception as e:
        logging.error(f"main: error {e}")
        sys.exit(200)
    if len(sys.argv) <= 1:
        logging.error("main: 'null' execution type.")
        sys.exit(100)
    conn = init_db()
    execution_type = sys.argv[1]
    if execution_type == "env":
        logging.info("main: running with execution type 'env'")
        get_environment()
    elif execution_type == "auth":
        logging.info("main: running with execution type 'auth'")
        authenticate_user(conn)
    elif execution_type == "acct":
        logging.info("main: running with execution type 'acct'")
        accounting_request("start", conn)
    elif execution_type == "update":
        logging.info("main: running with execution type 'update'")
        accounting_request("update", conn)
    elif execution_type == "stop":
        logging.info("main: running with execution type 'stop'")
        accounting_request("stop", conn)
    else:
        logging.error(f"main: '{execution_type}' execution type is unknown.")
        sys.exit(101)

if __name__ == "__main__":
    main()
