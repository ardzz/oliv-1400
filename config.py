#!/usr/bin/env python3
"""
Configuration management for Olivia Token Retriever
Updated: 2025-07-30 05:54:58 UTC
User: tututmar1211
"""

import os
from typing import Dict, Any

# Set the environment keys directly
OLIVIA_KEYS = {
    "MasterKey": "AuthenticationSystemMasterKey000",
    "QuizNotesKey": "QuizNotesAppDefaultKey0000000000",
    "ExamLMSKey": "ExamLMSAppDefaultKey000000000",
    "MemoEncryptedKey": "EncryptedNotesAppDefaultKey00000"
}

# Set environment variables
for key, value in OLIVIA_KEYS.items():
    os.environ[key] = value


class OliviaConfig:
    """Configuration manager for Olivia authentication system."""

    def __init__(self):
        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """Load configuration with embedded keys."""
        return {
            "metadata": {
                "updated": "2025-07-30 05:54:58 UTC",
                "user": "tututmar1211",
                "version": "2.0"
            },
            "server": {
                "host": os.getenv("OLIVIA_HOST", "127.0.0.1"),
                "port": int(os.getenv("OLIVIA_PORT", "1234")),  # Updated to match your system
                "timeout": int(os.getenv("OLIVIA_TIMEOUT", "10"))
            },
            "keys": OLIVIA_KEYS,
            "services": {
                "1": {
                    "name": "QuizNotes",
                    "description": "Quiz and Notes Management System",
                    "key": OLIVIA_KEYS["QuizNotesKey"]
                },
                "2": {
                    "name": "MemoEncrypted",
                    "description": "Encrypted Notes Application",
                    "key": OLIVIA_KEYS["MemoEncryptedKey"]
                },
                "3": {
                    "name": "ExamLMS",
                    "description": "Exam Learning Management System",
                    "key": OLIVIA_KEYS["ExamLMSKey"]
                }
            },
            "validation": {
                "username_min_length": 8,
                "username_max_length": 64,
                "password_min_length": 8,
                "password_max_length": 64,
                "allowed_chars": "alphanumeric_underscore"
            }
        }

    def get_server_config(self) -> Dict[str, Any]:
        """Get server configuration."""
        return self.config["server"]

    def get_service_config(self, service_id: str) -> Dict[str, Any]:
        """Get configuration for a specific service."""
        return self.config["services"].get(service_id, {})

    def get_all_services(self) -> Dict[str, Dict[str, Any]]:
        """Get all service configurations."""
        return self.config["services"]

    def get_validation_rules(self) -> Dict[str, Any]:
        """Get validation rules for credentials."""
        return self.config["validation"]

    def print_config(self):
        """Print current configuration."""
        print("🔧 Olivia Configuration:")
        print(f"  Updated: {self.config['metadata']['updated']}")
        print(f"  User: {self.config['metadata']['user']}")
        print(f"  Server: {self.config['server']['host']}:{self.config['server']['port']}")
        print(f"  Timeout: {self.config['server']['timeout']}s")
        print("\n📋 Services:")
        for service_id, service_info in self.config["services"].items():
            key_display = f"{service_info['key'][:20]}..."
            print(f"  {service_id}: {service_info['name']} ({key_display})")
        print(f"\n🔑 Master Key: {self.config['keys']['MasterKey'][:20]}...")


# Initialize configuration on import
config = OliviaConfig()