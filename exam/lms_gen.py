#!/usr/bin/env python3

import os
import sys
import json
import binascii
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

EXAM_LMS_KEY = os.environ.get("ExamLMSKey", "ExamLMSAppDefaultKey000000000")

def generate_exam_lms_token(username):
    """Generate token specifically for ExamLMS service"""
    if not (username.isalnum() and 7 < len(username) < 65):
        raise ValueError("Invalid username")

    try:
        app_key = get_random_bytes(32)

        # App token
        app_data = {"type": "APP_TOKEN", "user": binascii.hexlify(username.encode()).decode()}
        app_json = json.dumps(app_data, separators=(',', ':'))
        app_nonce = get_random_bytes(16)  # Exactly 16 bytes

        key_bytes = app_key[:32].ljust(32, b'\0')
        cipher = AES.new(key_bytes, AES.MODE_CTR, initial_value=app_nonce, nonce=b'')
        app_encrypted = cipher.encrypt(app_json.encode())
        app_token = binascii.hexlify(app_nonce).decode() + binascii.hexlify(app_encrypted).decode()

        # Service token
        service_data = {
            "type": "SERVICE_TOKEN",
            "user": binascii.hexlify(username.encode()).decode(),
            "key": binascii.hexlify(app_key).decode()
        }
        service_json = json.dumps(service_data, separators=(',', ':'))
        service_nonce = get_random_bytes(16)  # Exactly 16 bytes

        service_key_bytes = EXAM_LMS_KEY.encode()[:32].ljust(32, b'\0')
        cipher = AES.new(service_key_bytes, AES.MODE_CTR, initial_value=service_nonce, nonce=b'')
        service_encrypted = cipher.encrypt(service_json.encode())
        service_token = binascii.hexlify(service_nonce).decode() + binascii.hexlify(service_encrypted).decode()

        return f"{app_token}.{service_token}"

    except Exception as e:
        raise Exception(f"Token generation failed: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <username>")
        sys.exit(1)

    username = sys.argv[1]
    try:
        token = generate_exam_lms_token(username)
        print(token)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)