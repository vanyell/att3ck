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
    Generates synthetic but consistent identities for cross-scenario
    consistency (PERSONA_* template variables). Network/IP diversity lives in
    VariableManager's own pools (kinetix/core/vars.py), not here.
    """

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
        # Additional roster entries: widen identity/host cardinality so a
        # baseline run doesn't cycle the same ~11 named identities across
        # every session (see kinetix/core/vars.py for the bulk RANDOM_USER/
        # RANDOM_HOST/RANDOM_IP pools used for non-persona-anchored events).
        UserPersona("dana_sysadmin", "Systems Administrator", "IT", "litware.com", "DC-CORP-02", is_admin=True),
        UserPersona("carlos_netops", "Network Engineer", "IT", "litware.com", "NET-WS-01", is_admin=True),
        UserPersona("priya_sec", "Security Engineer", "Security", "litware.com", "SOC-WS-02", is_admin=True),
        UserPersona("liam_soc", "SOC Analyst", "Security", "litware.com", "SOC-WS-03"),
        UserPersona("wei_dev", "Developer", "Engineering", "litware.com", "DEV-SRV-02"),
        UserPersona("olga_devops", "DevOps Engineer", "Engineering", "litware.com", "DEV-SRV-03", is_admin=True),
        UserPersona("noah_qa", "QA Engineer", "Engineering", "litware.com", "DEV-WS-06"),
        UserPersona("fatima_finance", "Accountant", "Finance", "litware.com", "FIN-WS-02", is_sensitive=True),
        UserPersona("greg_ap", "Accounts Payable Clerk", "Finance", "litware.com", "FIN-WS-03", is_sensitive=True),
        UserPersona("elena_sales", "Account Executive", "Sales", "litware.com", "SALES-WS-02"),
        UserPersona("victor_sales", "Sales Engineer", "Sales", "litware.com", "SALES-WS-03"),
        UserPersona("mia_hr", "HR Generalist", "HR", "litware.com", "HR-WS-02", is_sensitive=True),
        UserPersona("samuel_recruiter", "Recruiter", "HR", "litware.com", "HR-WS-03"),
        UserPersona("cfo_office", "CFO", "Executive", "litware.com", "CFO-LAPTOP-01", is_sensitive=True),
        UserPersona("coo_office", "COO", "Executive", "litware.com", "COO-LAPTOP-01", is_sensitive=True),
        UserPersona("nina_legal", "Corporate Counsel", "Legal", "litware.com", "LEGAL-WS-01", is_sensitive=True),
        UserPersona("omar_marketing", "Marketing Manager", "Marketing", "litware.com", "MKT-WS-01"),
        UserPersona("ivy_support", "Support Engineer", "Support", "litware.com", "SUP-WS-01"),
        UserPersona("theo_product", "Product Manager", "Product", "litware.com", "PROD-WS-01", is_sensitive=True),
        UserPersona("zoe_ml", "AI Research Engineer", "AI Engineering", "litware.com", "MLOPS-WS-02", is_sensitive=True),
        UserPersona("intern_2", "Intern", "Marketing", "litware.com", "MKT-WS-02"),
        UserPersona("service_monitoring", "Monitoring Service", "IT", "litware.com", "SRV-MONITOR-01", is_admin=True),
        UserPersona("service_ci", "CI/CD Service", "Engineering", "litware.com", "SRV-CI-01", is_admin=True),
        UserPersona("ext_vendor", "External Vendor", "Procurement", "litware.com", "VEND-GW-01"),
    ]

    @classmethod
    def get_persona(cls, username: str = None) -> UserPersona:
        if username:
            for p in cls.PERSONAS:
                if p.username == username:
                    return p
        return random.choice(cls.PERSONAS)
