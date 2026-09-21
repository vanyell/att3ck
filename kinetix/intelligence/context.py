import random
import ipaddress
from typing import List

class UserPersona:
    def __init__(self, username: str, role: str, department: str, domain: str,
                 typical_host: str, is_admin: bool = False, is_sensitive: bool = False):
        self.username = username
        self.role = role
        self.department = department
        self.domain = domain
        self.typical_host = typical_host
        self.is_admin = is_admin
        self.is_sensitive = is_sensitive
        self.email = f"{username}@{domain}"

class ContextGenerator:
    """
    Generates synthetic but consistent identities and network context.
    Maintains a directory of user personas for cross-scenario consistency.
    """

    DOMAINS = ["litware.com", "contoso.com", "adatum.com", "northwindtraders.com"]

    PERSONAS = [
        UserPersona("admin_john", "IT Admin", "IT", "litware.com", "DC-CORP-01", is_admin=True),
        UserPersona("sarah_sec", "Security Analyst", "Security", "litware.com", "SOC-WS-01", is_admin=True),
        UserPersona("mike_dev", "Developer", "Engineering", "litware.com", "DEV-SRV-01", is_sensitive=True),
        UserPersona("linda_finance", "Finance Director", "Finance", "litware.com", "FIN-WS-01", is_sensitive=True),
        UserPersona("tom_sales", "Sales Rep", "Sales", "litware.com", "SALES-WS-01"),
        UserPersona("anna_hr", "HR Manager", "HR", "litware.com", "HR-WS-01", is_sensitive=True),
        UserPersona("ext_adm", "External Admin", "MSP", "litware.com", "MSP-GW-01", is_admin=True),
        UserPersona("service_backup", "Backup Service", "IT", "litware.com", "SRV-BACKUP-01", is_admin=True),
        UserPersona("ceo_office", "CEO", "Executive", "litware.com", "CEO-LAPTOP-01", is_sensitive=True),
        UserPersona("intern_1", "Intern", "Engineering", "litware.com", "DEV-WS-05"),
        UserPersona("raj_ml", "ML Engineer", "AI Engineering", "litware.com", "MLOPS-WS-01", is_sensitive=True),
    ]

    INTERNAL_SUBNETS = ["10.0.0.0/24", "192.168.1.0/24", "172.16.5.0/24"]
    EXTERNAL_IPS = ["8.8.8.8", "203.0.113.5", "198.51.100.12", "45.33.22.11"]
    _subnet_hosts_cache: dict = {}

    @classmethod
    def get_persona(cls, username: str = None) -> UserPersona:
        if username:
            for p in cls.PERSONAS:
                if p.username == username:
                    return p
        return random.choice(cls.PERSONAS)

    @classmethod
    def get_random_user(cls) -> str:
        return random.choice(cls.PERSONAS).username

    @classmethod
    def get_random_email(cls) -> str:
        p = random.choice(cls.PERSONAS)
        return p.email

    @classmethod
    def get_random_hostname(cls) -> str:
        return random.choice(cls.PERSONAS).typical_host

    @classmethod
    def get_random_internal_ip(cls) -> str:
        subnet_str = random.choice(cls.INTERNAL_SUBNETS)
        if subnet_str not in cls._subnet_hosts_cache:
            cls._subnet_hosts_cache[subnet_str] = list(ipaddress.ip_network(subnet_str).hosts())
        hosts = cls._subnet_hosts_cache[subnet_str]
        return str(random.choice(hosts[:100]))

    @classmethod
    def get_random_external_ip(cls) -> str:
        return random.choice(cls.EXTERNAL_IPS)

    @classmethod
    def get_random_tactic_variation(cls, base_cmd: str) -> str:
        variations = [
            f"{base_cmd}",
            f"{base_cmd} /quiet",
            f"{base_cmd} --silent -force",
            f"cmd.exe /c \"{base_cmd}\"",
            f"powershell -ExecutionPolicy Bypass -Command \"{base_cmd}\""
        ]
        return random.choice(variations)
