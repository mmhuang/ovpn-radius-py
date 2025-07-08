import os
import sys
import json
import logging
import subprocess
import random
import sqlite3
import binascii
import socket
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet

CONFIG_PATH = "/etc/openvpn/plugin/config.json"
DATABASE_PATH = "/etc/openvpn/plugin/db/ovpn-radius.db"

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
    c.execute("""
        CREATE TABLE IF NOT EXISTS OVPNClients(
            id TEXT NOT NULL UNIQUE,
            common_name TEXT NOT NULL,
            ip_address TEXT NULL,
            class_name TEXT NULL
        );
    """)
    conn.commit()
    return conn

# --- Helper functions ---
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
        
        # Initialize RADIUS client
        client = Client(
            server=server,
            authport=port,
            secret=config['Radius']['Authentication']['Secret'].encode(),
            dict=Dictionary()
        )
        
        # Create authentication request
        req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest)
        
        # Add attributes
        req["User-Name"] = username
        req["User-Password"] = password
        req["NAS-Identifier"] = config['ServerInfo']['Identifier']
        req["NAS-Port-Type"] = config['ServerInfo']['PortType']
        req["NAS-IP-Address"] = config['ServerInfo']['IpAddress']
        req["Service-Type"] = config['ServerInfo']['ServiceType']
        req["Framed-Protocol"] = "PPP"
        
        # Send request and get response
        reply = client.SendPacket(req)
        
        # Check if authentication was successful
        if reply.code != pyrad.packet.AccessAccept:
            logging.error("authenticate: failed to authenticate!")
            sys.exit(36)
        
        # Get Class attribute if present
        class_name = ""
        if "Class" in reply:
            class_data = reply["Class"][0]
            if isinstance(class_data, bytes):
                class_name = "0x" + class_data.hex()
        
        logging.info(f"authenticate: user '{username}' with class '{class_name}' is authenticated successfully")
        
        if not config['Radius'].get('AuthenticationOnly', False):
            new_id = f"{os.environ.get('untrusted_ip', '')}:{os.environ.get('untrusted_port', '')}"
            try:
                c = conn.cursor()
                c.execute(
                    "INSERT OR REPLACE INTO OVPNClients(id, common_name, ip_address, class_name) VALUES (?, ?, ?, ?)",
                    (new_id, username, "", class_name)
                )
                conn.commit()
                logging.info(f"authenticate: user '{username}' with class '{class_name}' data is saved.")
            except Exception as e:
                logging.error(f"authenticate: failed to save account data with error {e}")
                sys.exit(37)
    except Exception as e:
        logging.error(f"authenticate: Error: {e}")
        sys.exit(34)
    
    sys.exit(0)

def accounting_request(request_type, conn, session_id):
    logging.info(f"accountingRequest: prepare send request to {config['Radius']['Accounting']['Server']} with request type: {request_type}")
    user_id = f"{os.environ.get('trusted_ip', '')}:{os.environ.get('trusted_port', '')}"
    user_ip_address = os.environ.get('ifconfig_pool_remote_ip', '')
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM OVPNClients WHERE id = ?", (user_id,))
        row = c.fetchone()
        if not row:
            raise Exception("User not found")
        client = {
            "id": row[0],
            "common_name": row[1],
            "ip_address": row[2],
            "class_name": row[3]
        }
    except Exception as e:
        logging.error(f"accountingRequest: Error: {e}")
        sys.exit(60)
    
    if request_type == "start":
        logging.info(f"accountingRequest: update user data ip address to {user_ip_address} with Id {user_id}")
        try:
            c.execute("UPDATE OVPNClients SET ip_address = ? WHERE id = ?", (user_ip_address, user_id))
            conn.commit()
        except Exception as e:
            logging.error(f"accountingRequest: Error: {e}")
            sys.exit(61)
    
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
        srv = config['Radius']['Accounting']['Server'].split(':')
        server = srv[0]
        port = int(srv[1]) if len(srv) > 1 else 1813
        
        # Initialize RADIUS client
        client = Client(
            server=server,
            acctport=port,
            secret=config['Radius']['Accounting']['Secret'].encode(),
            dict=Dictionary()
        )
        
        # Create accounting request
        req = client.CreateAcctPacket()
        
        # Add attributes
        if client['class_name'].startswith('0x'):
            try:
                class_value = binascii.unhexlify(client['class_name'][2:])
                req["Class"] = class_value
            except:
                pass
        
        req["Acct-Session-Id"] = str(session_id)
        req["Acct-Status-Type"] = acct_status_type
        req["User-Name"] = client['common_name']
        req["Calling-Station-Id"] = config['ServerInfo']['IpAddress']
        req["NAS-Identifier"] = config['ServerInfo']['Identifier']
        req["Framed-IP-Address"] = user_ip_address
        
        if request_type == "stop":
            req["Acct-Terminate-Cause"] = 1  # User-Request
        
        # Send request and get response
        reply = client.SendPacket(req)
        
        # Check if accounting was successful
        if reply.code != pyrad.packet.AccountingResponse:
            logging.error("accountingRequest: no Accounting-Response received!")
            sys.exit(64)
        
        logging.info(f"accountingRequest: received Accounting-Response from {config['Radius']['Accounting']['Server']}")
        
        if request_type == "stop":
            try:
                c.execute("DELETE FROM OVPNClients WHERE id = ?", (user_id,))
                conn.commit()
                logging.info(f"accountingRequest: delete user data with Id {user_id}")
            except Exception as e:
                logging.error(f"accountingRequest: unable to delete data {e}")
                sys.exit(65)
                
        if request_type == "start":
            accounting_request("update", conn, session_id)
            
    except Exception as e:
        logging.error(f"accountingRequest: error: {e}")
        sys.exit(62)
    
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
        session_id = random.randint(0, 9999)
        accounting_request("start", conn, session_id)
    elif execution_type == "stop":
        logging.info("main: running with execution type 'stop'")
        session_id = random.randint(0, 9999)
        accounting_request("stop", conn, session_id)
    else:
        logging.error(f"main: '{execution_type}' execution type is unknown.")
        sys.exit(101)

if __name__ == "__main__":
    main()
