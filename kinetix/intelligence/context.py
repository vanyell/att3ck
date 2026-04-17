import random
import ipaddress
from typing import List, Optional

class ContextGenerator:
    """
    Generates synthetic but consistent identities and network context.
    """
    
    USERS = ["admin", "jsmith", "mross", "dbrown", "sjones", "service_acc", "backup_user"]
    HOSTNAMES = ["WS-LIT-01", "SRV-FILE-02", "DC-CORP-01", "DB-PROD-01", "LAPTOP-DEV-05"]
    INTERNAL_SUBNETS = ["10.0.0.0/24", "192.168.1.0/24", "172.16.5.0/24"]
    EXTERNAL_IPS = ["8.8.8.8", "203.0.113.5", "198.51.100.12", "45.33.22.11"]

    @classmethod
    def get_random_user(cls) -> str:
        return random.choice(cls.USERS)

    @classmethod
    def get_random_hostname(cls) -> str:
        return random.choice(cls.HOSTNAMES)

    @classmethod
    def get_random_internal_ip(cls) -> str:
        subnet = ipaddress.ip_network(random.choice(cls.INTERNAL_SUBNETS))
        # Get a random host IP in the subnet
        hosts = list(subnet.hosts())
        return str(random.choice(hosts[:100]))  # Stay in the lower range for "realism"

    @classmethod
    def get_random_external_ip(cls) -> str:
        return random.choice(cls.EXTERNAL_IPS)

    @classmethod
    def get_random_tactic_variation(cls, base_cmd: str) -> str:
        """
        Adds slight variations to CLI commands to avoid static signatures.
        """
        variations = [
            f"{base_cmd}",
            f"{base_cmd} /quiet",
            f"{base_cmd} --silent -force",
            f"cmd.exe /c \"{base_cmd}\"",
            f"powershell -ExecutionPolicy Bypass -Command \"{base_cmd}\""
        ]
        return random.choice(variations)
