import random

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
    ]

    @classmethod
    def get_persona(cls, username: str = None) -> UserPersona:
        if username:
            for p in cls.PERSONAS:
                if p.username == username:
                    return p
        return random.choice(cls.PERSONAS)
