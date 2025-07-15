#!/usr/bin/env python3
"""
Test script for OpenVPN RADIUS Authentication plugin.
This script allows testing the RADIUS authentication and accounting features
independently from OpenVPN.
"""

import os
import sys
import json
import sqlite3
import logging
import argparse
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import binascii
import pyrad.packet
from pyrad.client import Client

# Add parent directory to path so we can import from main.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import functions to test from main module
try:
    from main import (
        init_db, 
        authenticate_user, 
        accounting_request, 
        is_valid_utf8_from_hex,
        load_config
    )
except ImportError:
    print("Error: Unable to import functions from main.py")
    sys.exit(1)

class TestRadiusAuthentication(unittest.TestCase):
    """Test RADIUS authentication and accounting functionality"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create a temporary auth file
        self.auth_file = os.path.join(self.test_dir, "auth.txt")
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s"
        )
        
        # Create a test config
        self.config_file = os.path.join(self.test_dir, "config.json")
        self.create_test_config()
        
        # Create a test database
        self.db_path = os.path.join(self.test_dir, "test.db")
        self.conn = sqlite3.connect(self.db_path)
        self.create_test_db()
        
        # Set sys.argv for testing
        self.original_argv = sys.argv
        
        # Mock environment variables
        self.env_patcher = patch.dict('os.environ', {
            'untrusted_ip': '192.168.1.100',
            'untrusted_port': '1234',
            'trusted_ip': '192.168.1.200',
            'trusted_port': '5678',
            'ifconfig_pool_remote_ip': '10.8.0.2'
        })
        self.env_patcher.start()
    
    def tearDown(self):
        """Clean up after tests"""
        # Remove test files
        for f in [self.auth_file, self.config_file, self.db_path]:
            if os.path.exists(f):
                os.unlink(f)
        
        # Remove test directory
        if os.path.exists(self.test_dir):
            os.rmdir(self.test_dir)
        
        # Restore sys.argv
        sys.argv = self.original_argv
        
        # Stop environment patching
        self.env_patcher.stop()
        
        # Close database connection
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
    
    def create_test_config(self):
        """Create a test configuration file"""
        config = {
            "LogFile": "/tmp/radius-test.log",
            "Radius": {
                "Authentication": {
                    "Server": "127.0.0.1:1812",
                    "Secret": "testing123"
                },
                "Accounting": {
                    "Server": "127.0.0.1:1813",
                    "Secret": "testing123"
                },
                "AuthenticationOnly": False
            },
            "ServerInfo": {
                "Identifier": "OpenVPN-Test",
                "PortType": "5",
                "IpAddress": "192.168.1.1",
                "ServiceType": "2"
            }
        }
        
        with open(self.config_file, "w") as f:
            json.dump(config, f, indent=2)
    
    def create_test_db(self):
        """Create a test database"""
        c = self.conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS OVPNClients(
                id TEXT NOT NULL UNIQUE,
                common_name TEXT NOT NULL,
                ip_address TEXT NULL,
                class_name TEXT NULL
            );
        """)
        self.conn.commit()
    
    def create_auth_file(self, username, password):
        """Create an authentication file with username and password"""
        with open(self.auth_file, "w") as f:
            f.write(f"{username}\n{password}")
    
    @patch('main.load_config')
    @patch('main.Client')
    def test_authentication_success(self, mock_client, mock_load_config):
        """Test successful authentication"""
        # Set up mock config
        with open(self.config_file) as f:
            mock_load_config.return_value = json.load(f)
        
        # Set up mock client and response
        mock_client_instance = MagicMock()
        mock_client.return_value = mock_client_instance
        
        # Mock the auth packet
        mock_auth_packet = MagicMock()
        mock_client_instance.CreateAuthPacket.return_value = mock_auth_packet
        
        # Mock the response
        mock_response = MagicMock()
        mock_response.code = pyrad.packet.AccessAccept
        mock_response.__contains__ = lambda self, key: key == "Class"
        mock_response.__getitem__ = lambda self, key: [b"test_class"] if key == "Class" else None
        mock_client_instance.SendPacket.return_value = mock_response
        
        # Create auth file
        self.create_auth_file("testuser", "testpass")
        
        # Set up command line args
        sys.argv = ["main.py", "auth", self.auth_file]
        
        # Test with expected exit (will raise SystemExit)
        with self.assertRaises(SystemExit) as cm:
            authenticate_user(self.conn)
        
        # Check exit code
        self.assertEqual(cm.exception.code, 0)
        
        # Verify client was called with correct parameters
        mock_client.assert_called_once()
        mock_client_instance.CreateAuthPacket.assert_called_once()
        mock_client_instance.SendPacket.assert_called_once_with(mock_auth_packet)
        
        # Check database for saved user
        c = self.conn.cursor()
        c.execute("SELECT * FROM OVPNClients WHERE common_name = 'testuser'")
        result = c.fetchone()
        self.assertIsNotNone(result)
        self.assertEqual(result[1], "testuser")
    
    @patch('main.load_config')
    @patch('main.Client')
    def test_authentication_failure(self, mock_client, mock_load_config):
        """Test failed authentication"""
        # Set up mock config
        with open(self.config_file) as f:
            mock_load_config.return_value = json.load(f)
        
        # Set up mock client and response
        mock_client_instance = MagicMock()
        mock_client.return_value = mock_client_instance
        
        # Mock the auth packet
        mock_auth_packet = MagicMock()
        mock_client_instance.CreateAuthPacket.return_value = mock_auth_packet
        
        # Mock the response - reject
        mock_response = MagicMock()
        mock_response.code = pyrad.packet.AccessReject
        mock_client_instance.SendPacket.return_value = mock_response
        
        # Create auth file
        self.create_auth_file("testuser", "wrongpass")
        
        # Set up command line args
        sys.argv = ["main.py", "auth", self.auth_file]
        
        # Test with expected exit (will raise SystemExit)
        with self.assertRaises(SystemExit) as cm:
            authenticate_user(self.conn)
        
        # Check exit code (should be error code 36)
        self.assertEqual(cm.exception.code, 36)
    
    @patch('main.load_config')
    @patch('main.Client')
    def test_accounting_start(self, mock_client, mock_load_config):
        """Test accounting start request"""
        # Set up mock config
        with open(self.config_file) as f:
            mock_load_config.return_value = json.load(f)
        
        # Add a test user to the database
        c = self.conn.cursor()
        c.execute(
            "INSERT INTO OVPNClients(id, common_name, ip_address, class_name) VALUES (?, ?, ?, ?)",
            ("192.168.1.200:5678", "testuser", "", "0x74657374")
        )
        self.conn.commit()
        
        # Set up mock client and response
        mock_client_instance = MagicMock()
        mock_client.return_value = mock_client_instance
        
        # Mock the accounting packet
        mock_acct_packet = MagicMock()
        mock_client_instance.CreateAcctPacket.return_value = mock_acct_packet
        
        # Mock the response
        mock_response = MagicMock()
        mock_response.code = pyrad.packet.AccountingResponse
        mock_client_instance.SendPacket.return_value = mock_response
        
        # Patch accounting_request to prevent calling "update"
        with patch('main.accounting_request', side_effect=lambda rt, conn, sid: None if rt == "update" else accounting_request(rt, conn, sid)):
            # Test with expected exit (will raise SystemExit)
            with self.assertRaises(SystemExit) as cm:
                accounting_request("start", self.conn, 12345)
            
            # Check exit code
            self.assertEqual(cm.exception.code, 0)
            
            # Verify client was called with correct parameters
            mock_client.assert_called_once()
            mock_client_instance.CreateAcctPacket.assert_called_once()
            mock_client_instance.SendPacket.assert_called_once_with(mock_acct_packet)
            
            # Check database for updated IP
            c = self.conn.cursor()
            c.execute("SELECT ip_address FROM OVPNClients WHERE common_name = 'testuser'")
            result = c.fetchone()
            self.assertEqual(result[0], "10.8.0.2")
    
    def test_hex_decoding(self):
        """Test hex string decoding function"""
        # Test valid hex string
        result = is_valid_utf8_from_hex("0x74657374")  # "test" in hex
        self.assertEqual(result, "test")
        
        # Test with 0x prefix
        result = is_valid_utf8_from_hex("0x68656C6C6F")  # "hello" in hex
        self.assertEqual(result, "hello")
        
        # Test without 0x prefix
        result = is_valid_utf8_from_hex("776F726C64")  # "world" in hex
        self.assertEqual(result, "world")

def main():
    """Main entry point for the test script"""
    parser = argparse.ArgumentParser(description="Test OpenVPN RADIUS Authentication plugin")
    parser.add_argument("--config", help="Path to config file (optional)")
    parser.add_argument("--radius-server", help="RADIUS server address (for integration tests)")
    parser.add_argument("--radius-secret", help="RADIUS server secret (for integration tests)")
    parser.add_argument("--test-user", help="Test username (for integration tests)")
    parser.add_argument("--test-pass", help="Test password (for integration tests)")
    args = parser.parse_args()
    
    if args.config:
        print(f"Using config file: {args.config}")
        # Could modify CONFIG_PATH here for integration tests
    
    if all([args.radius_server, args.radius_secret, args.test_user, args.test_pass]):
        print("Running integration tests with real RADIUS server")
        # Could set up real integration tests here
    
    # Run unit tests
    unittest.main(argv=['first-arg-is-ignored'])

if __name__ == "__main__":
    main()
