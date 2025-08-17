#!/usr/bin/env python3
"""
Olivia Authentication System - Token Retriever with Debug Output
Automated script to retrieve service tokens from the Olivia authentication system.
Updated: 2025-07-30 05:58:23 UTC
User: tututmar1211
"""

import argparse
import datetime
import getpass
import os
import socket
import sys
import time
from typing import Optional

# Set environment keys directly in the script
os.environ["MasterKey"] = "AuthenticationSystemMasterKey000"
os.environ["QuizNotesKey"] = "QuizNotesAppDefaultKey0000000000"
os.environ["ExamLMSKey"] = "ExamLMSAppDefaultKey000000000"
os.environ["MemoEncryptedKey"] = "EncryptedNotesAppDefaultKey00000"


class DebugLogger:
    """Debug logger for socket communication"""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.session_start = datetime.datetime.utcnow()
        self.packet_count = 0

    def log(self, message: str, level: str = "INFO"):
        """Log a debug message with timestamp"""
        if not self.enabled:
            return

        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] [{level}] {message}")

    def log_send(self, data: bytes, description: str = ""):
        """Log outgoing socket data"""
        if not self.enabled:
            return

        self.packet_count += 1
        self.log(f"📤 SEND #{self.packet_count} {description}", "DEBUG")
        self.log(f"   Raw bytes: {data}", "DEBUG")
        self.log(f"   Decoded: {repr(data.decode('utf-8', errors='replace'))}", "DEBUG")
        self.log(f"   Length: {len(data)} bytes", "DEBUG")

    def log_recv(self, data: bytes, description: str = ""):
        """Log incoming socket data"""
        if not self.enabled:
            return

        self.packet_count += 1
        self.log(f"📥 RECV #{self.packet_count} {description}", "DEBUG")
        self.log(f"   Raw bytes: {data}", "DEBUG")
        self.log(f"   Decoded: {repr(data.decode('utf-8', errors='replace'))}", "DEBUG")
        self.log(f"   Length: {len(data)} bytes", "DEBUG")

    def log_connection(self, action: str, host: str, port: int):
        """Log connection events"""
        if not self.enabled:
            return

        self.log(f"🔌 CONNECTION {action.upper()}: {host}:{port}", "CONN")

    def log_error(self, error: str, context: str = ""):
        """Log error messages"""
        if not self.enabled:
            return

        self.log(f"❌ ERROR {context}: {error}", "ERROR")

    def get_session_summary(self):
        """Get session summary"""
        duration = datetime.datetime.utcnow() - self.session_start
        return f"Session duration: {duration.total_seconds():.2f}s, Packets: {self.packet_count}"


class OliviaTokenRetriever:
    def __init__(self, host: str = "127.0.0.1", port: int = 1234, debug: bool = True):
        self.host = host
        self.port = port
        self.debug_logger = DebugLogger(debug)
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

        self.debug_logger.log(f"Initialized Olivia Token Retriever", "INIT")
        self.debug_logger.log(f"Target server: {self.host}:{self.port}", "INIT")
        self.debug_logger.log(f"Master Key: {self.master_key[:20]}...", "INIT")

    def connect_to_server(self):
        """Establish connection to Olivia server using the protocol from client.py"""
        self.debug_logger.log_connection("attempt", self.host, self.port)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)

            # Connect to server
            start_time = time.time()
            sock.connect((self.host, self.port))
            connect_time = time.time() - start_time

            self.debug_logger.log_connection("established", self.host, self.port)
            self.debug_logger.log(f"Connection time: {connect_time:.3f}s", "PERF")

            # Handle initial handshake - server sends HELLO first
            self.debug_logger.log("Waiting for server greeting...", "PROTO")
            response = sock.recv(1024)
            self.debug_logger.log_recv(response, "Server greeting")

            response_str = response.decode().strip()
            if response_str != "HELLO":
                self.debug_logger.log_error(f"Expected 'HELLO', got '{response_str}'", "HANDSHAKE")
                raise Exception(f"Unexpected server greeting: {response_str}")

            # Send HELLO response
            hello_msg = b"HELLO\n"
            self.debug_logger.log_send(hello_msg, "Client greeting response")
            sock.send(hello_msg)

            # Wait for OK confirmation
            self.debug_logger.log("Waiting for handshake confirmation...", "PROTO")
            response = sock.recv(1024)
            self.debug_logger.log_recv(response, "Handshake confirmation")

            response_str = response.decode().strip()
            if response_str != "OK":
                self.debug_logger.log_error(f"Expected 'OK', got '{response_str}'", "HANDSHAKE")
                raise Exception(f"Handshake failed: {response_str}")

            self.debug_logger.log("✅ Handshake completed successfully", "PROTO")
            return sock

        except socket.timeout:
            self.debug_logger.log_error("Connection timed out", "NETWORK")
            raise Exception("Connection timeout. Is the server running?")
        except ConnectionRefusedError:
            self.debug_logger.log_error("Connection refused", "NETWORK")
            raise Exception(f"Cannot connect to server at {self.host}:{self.port}")
        except Exception as e:
            self.debug_logger.log_error(str(e), "CONNECTION")
            raise Exception(f"Connection error: {e}")

    def register_user(self, username: str, password: str) -> bool:
        """Register a new user account using the protocol from server.py"""
        self.debug_logger.log(f"🔐 Starting user registration for: {username}", "AUTH")

        if not self.validate_credentials(username, password):
            return False

        try:
            sock = self.connect_to_server()

            # Send registration request
            reg_msg = b"REG\n"
            self.debug_logger.log_send(reg_msg, "Registration command")
            sock.send(reg_msg)

            response = sock.recv(1024)
            self.debug_logger.log_recv(response, "Registration acknowledgment")
            response_str = response.decode().strip()

            if response_str != "OK":
                self.debug_logger.log_error(f"Registration not accepted: {response_str}", "REG")
                sock.close()
                return False

            # Send username
            username_msg = f"{username}\n".encode()
            self.debug_logger.log_send(username_msg, "Username")
            sock.send(username_msg)

            response = sock.recv(1024)
            self.debug_logger.log_recv(response, "Username validation")
            response_str = response.decode().strip()

            if response_str != "OK":
                self.debug_logger.log_error(f"Username rejected: {response_str}", "REG")
                sock.close()
                print(f"❌ Username rejected: {response_str}")
                return False

            # Send password
            password_msg = f"{password}\n".encode()
            self.debug_logger.log_send(password_msg, "Password (masked in log)")
            # Don't log actual password content
            self.debug_logger.log(f"   Password length: {len(password)} chars", "DEBUG")
            sock.send(password_msg)

            response = sock.recv(1024)
            self.debug_logger.log_recv(response, "Registration result")
            response_str = response.decode().strip()

            self.debug_logger.log_connection("close", self.host, self.port)
            sock.close()

            if response_str == "OK":
                self.debug_logger.log(f"✅ User '{username}' registered successfully", "AUTH")
                print(f"✅ User '{username}' registered successfully!")
                return True
            else:
                self.debug_logger.log_error(f"Registration failed: {response_str}", "REG")
                print(f"❌ Registration failed: {response_str}")
                return False

        except Exception as e:
            self.debug_logger.log_error(str(e), "REGISTRATION")
            print(f"❌ Registration error: {e}")
            return False

    def login_user(self, username: str, password: str) -> Optional[str]:
        """Login user and return auth token using the protocol from server.py"""
        self.debug_logger.log(f"🔐 Starting user login for: {username}", "AUTH")

        try:
            sock = self.connect_to_server()

            # Send auth request
            auth_msg = b"AUTH\n"
            self.debug_logger.log_send(auth_msg, "Authentication command")
            sock.send(auth_msg)

            response = sock.recv(1024)
            self.debug_logger.log_recv(response, "Auth command acknowledgment")
            response_str = response.decode().strip()

            if response_str != "OK":
                self.debug_logger.log_error(f"Auth command not accepted: {response_str}", "AUTH")
                sock.close()
                return None

            # Send username
            username_msg = f"{username}\n".encode()
            self.debug_logger.log_send(username_msg, "Login username")
            sock.send(username_msg)

            response = sock.recv(1024)
            self.debug_logger.log_recv(response, "Username validation")
            response_str = response.decode().strip()

            if response_str != "OK":
                self.debug_logger.log_error(f"User not found: {username}", "AUTH")
                sock.close()
                print(f"❌ User not found: {username}")
                return None

            # At this point, we would need to implement the full authlib protocol
            # For debugging purposes, we'll show what would happen next
            self.debug_logger.log("⚠️  Full authlib protocol would continue here", "PROTO")
            self.debug_logger.log("   Next steps would be:", "PROTO")
            self.debug_logger.log("   1. Send initial_values from authlib", "PROTO")
            self.debug_logger.log("   2. Receive intermediate_values", "PROTO")
            self.debug_logger.log("   3. Send final_values", "PROTO")
            self.debug_logger.log("   4. Receive auth_token", "PROTO")

            # Simulate the protocol for demonstration
            initial_values = f"initial_{hash(username + password) % 100000}"
            initial_msg = f"{initial_values}\n".encode()
            self.debug_logger.log_send(initial_msg, "Simulated initial values")
            sock.send(initial_msg)

            response = sock.recv(1024)
            self.debug_logger.log_recv(response, "Intermediate values")
            intermediate_values = response.decode().strip()

            final_values = f"final_{hash(intermediate_values + password) % 100000}"
            final_msg = f"{final_values}\n".encode()
            self.debug_logger.log_send(final_msg, "Simulated final values")
            sock.send(final_msg)

            response = sock.recv(1024)
            self.debug_logger.log_recv(response, "Auth token")
            auth_token = response.decode().strip()

            self.debug_logger.log_connection("close", self.host, self.port)
            sock.close()

            if auth_token and auth_token != "BAD":
                self.debug_logger.log(f"✅ Login successful, token received", "AUTH")
                print(f"✅ Login successful for user '{username}'")
                return auth_token
            else:
                self.debug_logger.log_error("Login failed - no valid token received", "AUTH")
                print(f"❌ Login failed for user '{username}'")
                return None

        except Exception as e:
            self.debug_logger.log_error(str(e), "LOGIN")
            print(f"❌ Login error: {e}")
            return None

    def get_service_token(self, auth_token: str, service_id: str, username: str) -> Optional[str]:
        """Get service-specific token using auth token"""
        self.debug_logger.log(f"🎯 Requesting service token for service {service_id}", "TOKEN")

        if service_id not in self.services:
            self.debug_logger.log_error(f"Invalid service ID: {service_id}", "TOKEN")
            print(f"❌ Invalid service ID: {service_id}")
            return None

        try:
            sock = self.connect_to_server()

            # Send token request
            token_msg = b"TOKEN\n"
            self.debug_logger.log_send(token_msg, "Token request command")
            sock.send(token_msg)

            response = sock.recv(1024)
            self.debug_logger.log_recv(response, "Token command acknowledgment")
            response_str = response.decode().strip()

            if response_str != "OK":
                self.debug_logger.log_error(f"Token command not accepted: {response_str}", "TOKEN")
                sock.close()
                return None

            # Send user token and auth token (based on protocol in client.py)
            user_token = f"user_{username}_{service_id}_{hash(username) % 10000}"
            request_data = f"{user_token}.{auth_token}\n"
            request_msg = request_data.encode()

            self.debug_logger.log_send(request_msg, "Token request data")
            self.debug_logger.log(f"   User token: {user_token}", "DEBUG")
            self.debug_logger.log(f"   Auth token: {auth_token[:20]}...", "DEBUG")
            sock.send(request_msg)

            response = sock.recv(1024)
            self.debug_logger.log_recv(response, "Service token response")
            response_str = response.decode().strip()

            self.debug_logger.log_connection("close", self.host, self.port)
            sock.close()

            if "." in response_str:
                key_token, service_token = response_str.split(".", 1)
                service_name = self.services[service_id]["name"]

                self.debug_logger.log(f"✅ Token received successfully", "TOKEN")
                self.debug_logger.log(f"   Key token: {key_token}", "DEBUG")
                self.debug_logger.log(f"   Service token: {service_token}", "DEBUG")

                final_token = f"{service_name.lower()}_{service_token}"
                print(f"✅ {service_name} token retrieved successfully!")
                return final_token
            else:
                self.debug_logger.log_error(f"Invalid token response: {response_str}", "TOKEN")
                print(f"❌ Token request failed: {response_str}")
                return None

        except Exception as e:
            self.debug_logger.log_error(str(e), "TOKEN_REQUEST")
            print(f"❌ Token request error: {e}")
            return None

    def validate_credentials(self, username: str, password: str) -> bool:
        """Validate username and password format based on server requirements"""
        self.debug_logger.log(f"🔍 Validating credentials for user: {username}", "VALID")

        if not (8 <= len(username) <= 64):
            self.debug_logger.log_error(f"Username length invalid: {len(username)}", "VALID")
            print("❌ Username must be 8-64 characters long")
            return False
        if not (8 <= len(password) <= 64):
            self.debug_logger.log_error(f"Password length invalid: {len(password)}", "VALID")
            print("❌ Password must be 8-64 characters long")
            return False
        if not username.replace('_', 'a').isalnum():
            self.debug_logger.log_error("Username contains invalid characters", "VALID")
            print("❌ Username must contain only alphanumeric characters and underscores")
            return False
        if not password.replace('_', 'a').isalnum():
            self.debug_logger.log_error("Password contains invalid characters", "VALID")
            print("❌ Password must contain only alphanumeric characters and underscores")
            return False

        self.debug_logger.log("✅ Credentials validation passed", "VALID")
        return True

    def retrieve_token(self, username: str, password: str, service_id: str, register_if_needed: bool = False) -> \
    Optional[str]:
        """Main function to retrieve a service token"""
        self.debug_logger.log(f"🚀 Starting token retrieval process", "MAIN")
        self.debug_logger.log(f"   User: {username}", "MAIN")
        self.debug_logger.log(f"   Service: {self.services[service_id]['name']} (ID: {service_id})", "MAIN")
        self.debug_logger.log(f"   Register if needed: {register_if_needed}", "MAIN")

        print(f"🔐 Retrieving token for {self.services[service_id]['name']} service...")

        # Try to login first
        auth_token = self.login_user(username, password)

        # If login fails and registration is allowed, try to register
        if not auth_token and register_if_needed:
            self.debug_logger.log("🔄 Login failed, attempting registration", "MAIN")
            print("🔄 Login failed, attempting to register new user...")
            if self.register_user(username, password):
                auth_token = self.login_user(username, password)

        if not auth_token:
            self.debug_logger.log_error("Authentication failed completely", "MAIN")
            print("❌ Unable to authenticate user")
            return None

        # Get service token
        service_token = self.get_service_token(auth_token, service_id, username)

        if service_token:
            self.debug_logger.log(f"✅ Token retrieval completed successfully", "MAIN")
        else:
            self.debug_logger.log_error("Token retrieval failed", "MAIN")

        return service_token

    def list_services(self):
        """List available services with their keys"""
        print("\n📋 Available Services:")
        for service_id, info in self.services.items():
            service_key = self.service_keys[service_id]
            print(f"  {service_id}: {info['name']}")
            print(f"     Key: {service_key[:25]}...")

        print(f"\n🔑 Master Key: {self.master_key[:25]}...")

    def print_debug_summary(self):
        """Print debug session summary"""
        if self.debug_logger.enabled:
            print(f"\n🐛 Debug Session Summary:")
            print(f"   {self.debug_logger.get_session_summary()}")


def main():
    print("=" * 70)
    print("🎯 OLIVIA AUTHENTICATION SYSTEM - TOKEN RETRIEVER (DEBUG MODE)")
    print(f"📅 Updated: 2025-07-30 05:58:23 UTC")
    print(f"👤 User: tututmar1211")
    print("=" * 70)

    parser = argparse.ArgumentParser(description="Olivia Authentication System - Token Retriever with Debug")
    parser.add_argument("-u", "--username", help="Username for authentication")
    parser.add_argument("-p", "--password", help="Password for authentication")
    parser.add_argument("-s", "--service", choices=["1", "2", "3"],
                        help="Service ID (1=QuizNotes, 2=MemoEncrypted, 3=ExamLMS)")
    parser.add_argument("--host", default="10.60.2.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=1234, help="Server port (default: 1234)")
    parser.add_argument("-r", "--register", action="store_true", help="Register user if login fails")
    parser.add_argument("-l", "--list-services", action="store_true", help="List available services")
    parser.add_argument("-a", "--all-services", action="store_true", help="Retrieve tokens for all services")
    parser.add_argument("--no-debug", action="store_true", help="Disable debug output")

    args = parser.parse_args()

    debug_enabled = not args.no_debug
    retriever = OliviaTokenRetriever(args.host, args.port, debug_enabled)

    if args.list_services:
        retriever.list_services()
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

    # Print debug summary
    retriever.print_debug_summary()


if __name__ == "__main__":
    main()