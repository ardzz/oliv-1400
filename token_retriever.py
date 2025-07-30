#!/usr/bin/env python3
"""
Olivia Authentication System - Token Retriever
Automated script to retrieve service tokens from the Olivia authentication system.
Updated: 2025-07-30 05:54:58 UTC
User: tututmar1211
"""

import socket
import json
import os
import sys
import argparse
import getpass
from typing import Optional, Dict, Any

# Set environment keys directly in the script
os.environ["MasterKey"] = "AuthenticationSystemMasterKey000"
os.environ["QuizNotesKey"] = "QuizNotesAppDefaultKey0000000000"
os.environ["ExamLMSKey"] = "ExamLMSAppDefaultKey000000000"
os.environ["MemoEncryptedKey"] = "EncryptedNotesAppDefaultKey00000"


class OliviaTokenRetriever:
    def __init__(self, host: str = "10.60.2.1", port: int = 1234):  # Updated default port to match your system
        self.host = host
        self.port = port
        self.services = {
            "1": {"name": "QuizNotes", "key": "QuizNotesKey"},
            "2": {"name": "MemoEncrypted", "key": "MemoEncryptedKey"},
            "3": {"name": "ExamLMS", "key": "ExamLMSKey"}
        }

        # Authentication keys (set directly in script)
        self.master_key = os.environ["MasterKey"]
        self.service_keys = {
            "1": os.environ["QuizNotesKey"],
            "2": os.environ["MemoEncryptedKey"],
            "3": os.environ["ExamLMSKey"]
        }

        print(f"🔧 Initialized with Master Key: {self.master_key[:20]}...")

    def connect_to_server(self):
        """Establish connection to Olivia server using the protocol from client.py"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))

            # Handle initial handshake
            response = sock.recv(1024).decode().strip()
            if response != "HELLO":
                raise Exception(f"Unexpected server greeting: {response}")

            sock.send(b"HELLO\n")
            response = sock.recv(1024).decode().strip()
            if response != "OK":
                raise Exception(f"Handshake failed: {response}")

            return sock

        except socket.timeout:
            raise Exception("Connection timeout. Is the server running?")
        except ConnectionRefusedError:
            raise Exception(f"Cannot connect to server at {self.host}:{self.port}")
        except Exception as e:
            raise Exception(f"Connection error: {e}")

    def register_user(self, username: str, password: str) -> bool:
        """Register a new user account using the protocol from server.py"""
        if not self.validate_credentials(username, password):
            return False

        try:
            sock = self.connect_to_server()

            # Send registration request
            sock.send(b"REG\n")
            response = sock.recv(1024).decode().strip()
            if response != "OK":
                sock.close()
                return False

            # Send username
            sock.send(f"{username}\n".encode())
            response = sock.recv(1024).decode().strip()
            if response != "OK":
                sock.close()
                print(f"❌ Username rejected: {response}")
                return False

            # Send password
            sock.send(f"{password}\n".encode())
            response = sock.recv(1024).decode().strip()
            sock.close()

            if response == "OK":
                print(f"✅ User '{username}' registered successfully!")
                return True
            else:
                print(f"❌ Registration failed: {response}")
                return False

        except Exception as e:
            print(f"❌ Registration error: {e}")
            return False

    def login_user(self, username: str, password: str) -> Optional[str]:
        """Login user and return auth token using the protocol from server.py"""
        try:
            sock = self.connect_to_server()

            # Send auth request
            sock.send(b"AUTH\n")
            response = sock.recv(1024).decode().strip()
            if response != "OK":
                sock.close()
                return None

            # Send username
            sock.send(f"{username}\n".encode())
            response = sock.recv(1024).decode().strip()
            if response != "OK":
                sock.close()
                print(f"❌ User not found: {username}")
                return None

            # This is where we'd need to implement the authlib protocol
            # For now, we'll simulate the auth flow
            print(f"⚠️  Note: Full authentication protocol requires authlib implementation")
            print(f"✅ Login simulation successful for user '{username}'")

            # Simulate auth token (in real implementation, this would come from authlib)
            auth_token = f"auth_{username}_{hash(password) % 100000}"
            sock.close()
            return auth_token

        except Exception as e:
            print(f"❌ Login error: {e}")
            return None

    def get_service_token(self, auth_token: str, service_id: str, username: str) -> Optional[str]:
        """Get service-specific token using auth token"""
        if service_id not in self.services:
            print(f"❌ Invalid service ID: {service_id}")
            return None

        try:
            sock = self.connect_to_server()

            # Send token request
            sock.send(b"TOKEN\n")
            response = sock.recv(1024).decode().strip()
            if response != "OK":
                sock.close()
                return None

            # Send user token and auth token (simulated format)
            user_token = f"user_{username}_{service_id}"
            request_data = f"{user_token}.{auth_token}\n"
            sock.send(request_data.encode())

            response = sock.recv(1024).decode().strip()
            sock.close()

            if "." in response:
                key_token, service_token = response.split(".", 1)
                service_name = self.services[service_id]["name"]
                print(f"✅ {service_name} token retrieved successfully!")
                return f"{service_name.lower()}_{service_token}"
            else:
                print(f"❌ Token request failed: {response}")
                return None

        except Exception as e:
            print(f"❌ Token request error: {e}")
            return None

    def validate_credentials(self, username: str, password: str) -> bool:
        """Validate username and password format based on server requirements"""
        if not (8 <= len(username) <= 64):
            print("❌ Username must be 8-64 characters long")
            return False
        if not (8 <= len(password) <= 64):
            print("❌ Password must be 8-64 characters long")
            return False
        if not username.replace('_', 'a').isalnum():  # Allow underscores
            print("❌ Username must contain only alphanumeric characters and underscores")
            return False
        if not password.replace('_', 'a').isalnum():  # Allow underscores
            print("❌ Password must contain only alphanumeric characters and underscores")
            return False
        return True

    def retrieve_token(self, username: str, password: str, service_id: str, register_if_needed: bool = False) -> \
    Optional[str]:
        """Main function to retrieve a service token"""
        print(f"🔐 Retrieving token for {self.services[service_id]['name']} service...")

        # Try to login first
        auth_token = self.login_user(username, password)

        # If login fails and registration is allowed, try to register
        if not auth_token and register_if_needed:
            print("🔄 Login failed, attempting to register new user...")
            if self.register_user(username, password):
                auth_token = self.login_user(username, password)

        if not auth_token:
            print("❌ Unable to authenticate user")
            return None

        # Get service token
        service_token = self.get_service_token(auth_token, service_id, username)
        return service_token

    def list_services(self):
        """List available services with their keys"""
        print("\n📋 Available Services:")
        for service_id, info in self.services.items():
            service_key = self.service_keys[service_id]
            print(f"  {service_id}: {info['name']}")
            print(f"     Key: {service_key[:25]}...")

        print(f"\n🔑 Master Key: {self.master_key[:25]}...")

    def quick_token_demo(self):
        """Quick demonstration using existing user data"""
        print("🚀 Quick Token Demo Mode")
        print("Using existing user from your system...")

        # Use one of the existing users from the files
        demo_username = "05nYPCL2Pvk8RC9a"  # From your user files
        demo_password = "demopass123"  # Simulated password

        print(f"Demo User: {demo_username}")

        # Try all services
        for service_id in ["1", "2", "3"]:
            service_name = self.services[service_id]["name"]
            print(f"\n--- {service_name} Service ---")

            # Simulate token generation
            token = f"{service_name.lower()}_token_{hash(demo_username + service_id) % 1000000}"
            print(f"🎯 Simulated Token: {token}")


def main():
    print("=" * 60)
    print("🎯 OLIVIA AUTHENTICATION SYSTEM - TOKEN RETRIEVER")
    print(f"📅 Updated: 2025-07-30 05:54:58 UTC")
    print(f"👤 User: tututmar1211")
    print("=" * 60)

    parser = argparse.ArgumentParser(description="Olivia Authentication System - Token Retriever")
    parser.add_argument("-u", "--username", help="Username for authentication")
    parser.add_argument("-p", "--password", help="Password for authentication")
    parser.add_argument("-s", "--service", choices=["1", "2", "3"],
                        help="Service ID (1=QuizNotes, 2=MemoEncrypted, 3=ExamLMS)")
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=1234, help="Server port (default: 1234)")
    parser.add_argument("-r", "--register", action="store_true", help="Register user if login fails")
    parser.add_argument("-l", "--list-services", action="store_true", help="List available services")
    parser.add_argument("-a", "--all-services", action="store_true", help="Retrieve tokens for all services")
    parser.add_argument("-d", "--demo", action="store_true", help="Run quick demo mode")

    args = parser.parse_args()

    retriever = OliviaTokenRetriever(args.host, args.port)

    if args.list_services:
        retriever.list_services()
        return

    if args.demo:
        retriever.quick_token_demo()
        return

    # Get credentials
    username = args.username
    password = args.password

    if not username:
        username = input("Username: ")

    if not password:
        password = getpass.getpass("Password: ")

    if not retriever.validate_credentials(username, password):
        sys.exit(1)

    # Determine which services to get tokens for
    services_to_process = []
    if args.all_services:
        services_to_process = ["1", "2", "3"]
    elif args.service:
        services_to_process = [args.service]
    else:
        retriever.list_services()
        service_choice = input("\nEnter service ID (1-3): ").strip()
        if service_choice in ["1", "2", "3"]:
            services_to_process = [service_choice]
        else:
            print("❌ Invalid service selection")
            sys.exit(1)

    # Retrieve tokens
    print(f"\n🚀 Starting token retrieval for user: {username}")
    tokens = {}

    for service_id in services_to_process:
        service_name = retriever.services[service_id]["name"]
        print(f"\n--- Processing {service_name} ---")

        token = retriever.retrieve_token(username, password, service_id, args.register)
        if token:
            tokens[service_name] = token
            print(f"🎯 Token: {token}")
        else:
            print(f"❌ Failed to retrieve token for {service_name}")

    # Summary
    print(f"\n📊 Summary:")
    print(f"Successfully retrieved {len(tokens)} out of {len(services_to_process)} tokens")

    if tokens:
        print("\n🔑 Retrieved Tokens:")
        for service_name, token in tokens.items():
            print(f"  {service_name}: {token}")


if __name__ == "__main__":
    main()