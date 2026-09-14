import random
import uuid
from pathlib import Path
from typing import Optional
from kinetix.intelligence.context import ContextGenerator
from kinetix.intelligence.corpus import CorpusProfile, get_profile

# For each RANDOM_* placeholder below, corpus-mined (table, field) pairs to try
# before falling back to the static pool. Only fields the miner classifies as
# "freeform" ever have real values to sample -- identifier-like placeholders
# (RANDOM_HOST, RANDOM_USER, RANDOM_EMAIL, RANDOM_IP, ...) are deliberately
# absent here and always use the static pools, since mined profiles never
# carry real entity values for those (see kinetix/intelligence/corpus.py).
CORPUS_FIELD_CANDIDATES = {
    "RANDOM_UA": [
        ("SigninLogs", "UserAgent"),
        ("AADNonInteractiveUserSignInLogs", "UserAgent"),
        ("CloudAppEvents", "UserAgent"),
        ("OfficeActivity", "UserAgent"),
    ],
    "RANDOM_URL": [
        ("CommonSecurityLog", "RequestURL"),
        ("OfficeActivity", "OfficeObjectId"),
        ("CloudAppEvents", "ObjectId"),
        ("W3CIISLog", "csUriStem"),
        ("DeviceNetworkEvents", "EventData.url"),  # from mined BITS-Client EVTX records
    ],
}

class VariableManager:
    """
    Handles dynamic placeholder replacement in scenario files.
    """
    def __init__(self, corpus_dir: Optional[Path] = None):
        self._corpus: CorpusProfile = get_profile(corpus_dir)
        self._set_session_vars()
        self._set_persona_vars()
        self.ip_pool = [f"192.168.1.{i}" for i in range(10, 250)]
        self.host_pool = [f"WS-PROD-{i:03d}" for i in range(1, 100)]
        self.server_pool = [f"SRV-{i:03d}" for i in range(1, 30)]
        self.linux_host_pool = [f"web-{i:02d}.prod" for i in range(1, 20)] + [f"db-{i:02d}.prod" for i in range(1, 10)] + [f"app-{i:02d}.prod" for i in range(1, 15)] + [f"worker-{i:02d}.prod" for i in range(1, 10)]
        self.mac_host_pool = [f"MBP-{user.capitalize()}" for user in ["jsmith", "ajones", "tclark", "lwhite", "kmiller", "egarcia"]] + [f"Mac-mini-{i:02d}" for i in range(1, 6)]
        self.user_pool = [
            "jsmith", "ajones", "mrobinson", "tclark", "lwhite", "kmiller", "bdavis", 
            "rwilson", "ptaylor", "handerson", "sthomas", "jmoore", "smartin", "cjackson",
            "nthompson", "egarcia", "smartinez", "crobinson", "dclark", "mrodriguez",
            "llewis", "jlee", "kwalker", "ahall", "ballen", "young", "pking", "jwright",
            "sscott", "ctorres", "mnguyen", "phill", "jflores", "mgreen", "badams",
            "nelson", "abaker", "shall", "drivera", "mcampbell", "jmitchell", "ccarter",
            "droberts", "jgomez", "mphillips", "jevans", "sturner", "rdiaz", "rparker",
            "bcruz", "dedwards", "mcollins", "jreyes", "astewart", "bmorris", "mmorales",
            "jmurphy", "fcook", "rrogers", "mgutierrez", "jortiz", "morgan", "jcooper",
            "ppeterson", "gbailey", "rreed", "hkelly", "khoward", "ramos", "jcox", "award",
            "anna.petrov", "bjensen", "c.williams", "d.gupta", "e.kim", "f.martinez",
            "g.anderson", "h.nguyen", "i.patel", "j.taylor"
        ]
        self.user_agent_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.39 Mobile Safari/537.36",
            "Python/3.13 aiohttp/3.9.5",
            "curl/8.12.1",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 GPT-4o",
            "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.18324; Pro)",
            "AzureDevOps/2025-11-01 (Windows; git)",
            "Okta-OLA/1.0"
        ]
        self.email_domains = ["litware.com", "contoso.com", "adatum.com", "northwindtraders.com",
                               "fabrikam.com", "tailspintoys.com", "wideworldimporters.com"]
        self.org_names = ["Litware Inc", "Contoso Ltd", "Adatum Corp", "Northwind Traders",
                          "Fabrikam Inc", "Tailspin Toys", "Wide World Importers"]
        self.url_pool = [
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://outlook.office365.com/owa/",
            "https://contoso.sharepoint.com/sites/sales",
            "https://teams.microsoft.com/",
            "https://portal.azure.com/",
            "https://graph.microsoft.com/v1.0/users",
            "https://api.github.com/repos/org/repo",
            "https://docs.google.com/document/d/abc123",
            "https://www.linkedin.com/in/",
            "https://app.powerbi.com/home"
        ]
        self.location_pool = ["US", "EU", "GB", "DE", "FR", "JP", "AU", "BR", "IN", "CA", "NL", "SG"]
        self.city_pool = ["Seattle", "Redmond", "New York", "San Francisco", "London", "Dublin",
                          "Amsterdam", "Tokyo", "Sydney", "Toronto", "Mumbai", "Berlin", "Paris",
                          "Singapore", "Sao Paulo"]
        self.ai_model_pool = ["GPT-4o", "GPT-4o-mini", "Claude-3.5-Sonnet", "Claude-3-Opus",
                              "Gemini-2.0-Ultra", "Gemini-2.0-Flash", "Llama-3.1-405B",
                              "Llama-3.1-70B", "Mistral-Large-2", "DeepSeek-R1", "Cohere-Command-R+"]

    def _set_persona_vars(self):
        persona = ContextGenerator.get_persona()
        self.persona_vars = {
            "PERSONA_USER": persona.username,
            "PERSONA_HOST": persona.typical_host,
            "PERSONA_EMAIL": persona.email,
            "PERSONA_ROLE": persona.role,
            "PERSONA_DEPT": persona.department,
            "PERSONA_DOMAIN": persona.domain,
            "PERSONA_IS_ADMIN": str(persona.is_admin).lower(),
            "PERSONA_IS_SENSITIVE": str(persona.is_sensitive).lower(),
        }

    def _set_session_vars(self):
        self.session_vars = {
            "SESSION_ID": str(uuid.uuid4()),
            "CNC_IP": f"91.228.{random.randint(1,254)}.{random.randint(1,254)}",
            "MALICIOUS_DOMAIN": random.choice(["evil-cnc.net", "update-msft.com", "security-alert.io",
                                                "portal-auth-verify.com", "docshare-pro.com", "teams-secure-update.com"]),
            "MALICIOUS_URL": random.choice([
                "https://evil-cnc.net/update.php",
                "https://portal-auth-verify.com/login.php",
                "https://docshare-pro.com/share/doc",
                "https://teams-secure-update.com/dl/teams_update.msi"
            ]),
            "DEEPFAKE_PHONE": f"+1-{random.randint(200,999)}-{random.randint(100,999)}-{random.randint(1000,9999)}"
        }

    def _corpus_or_pool(self, placeholder: str, pool: list) -> str:
        """Sample from a mined corpus profile if it has this field, else the static pool."""
        pairs = CORPUS_FIELD_CANDIDATES.get(placeholder)
        if pairs:
            value = self._corpus.sample_first(pairs)
            if value is not None:
                return value
        return random.choice(pool)

    def resolve(self, value: any) -> any:
        if isinstance(value, str):
            # 1. Persona Templates (consistent identity coupling)
            for k, v in self.persona_vars.items():
                value = value.replace(f"{{{{{k}}}}}", v)

            # 2. System/Session Templates
            for k, v in self.session_vars.items():
                value = value.replace(f"{{{{{k}}}}}", v)
            
            # 3. Random Generators
            if "{{RANDOM_IP}}" in value:
                value = value.replace("{{RANDOM_IP}}", random.choice(self.ip_pool))
            if "{{RANDOM_HOST}}" in value:
                value = value.replace("{{RANDOM_HOST}}", random.choice(self.host_pool))
            if "{{RANDOM_SERVER}}" in value:
                value = value.replace("{{RANDOM_SERVER}}", random.choice(self.server_pool))
            if "{{RANDOM_LINUX_HOST}}" in value:
                value = value.replace("{{RANDOM_LINUX_HOST}}", random.choice(self.linux_host_pool))
            if "{{RANDOM_MAC_HOST}}" in value:
                value = value.replace("{{RANDOM_MAC_HOST}}", random.choice(self.mac_host_pool))
            if "{{RANDOM_USER}}" in value:
                value = value.replace("{{RANDOM_USER}}", random.choice(self.user_pool))
            if "{{RANDOM_EMAIL}}" in value:
                user = random.choice(self.user_pool)
                domain = random.choice(self.email_domains)
                value = value.replace("{{RANDOM_EMAIL}}", f"{user}@{domain}")
            if "{{RANDOM_ORG}}" in value:
                value = value.replace("{{RANDOM_ORG}}", random.choice(self.org_names))
            if "{{RANDOM_UA}}" in value:
                value = value.replace("{{RANDOM_UA}}", self._corpus_or_pool("RANDOM_UA", self.user_agent_pool))
            if "{{RANDOM_URL}}" in value:
                value = value.replace("{{RANDOM_URL}}", self._corpus_or_pool("RANDOM_URL", self.url_pool))
            if "{{RANDOM_LOCATION}}" in value:
                value = value.replace("{{RANDOM_LOCATION}}", random.choice(self.location_pool))
            if "{{RANDOM_CITY}}" in value:
                value = value.replace("{{RANDOM_CITY}}", random.choice(self.city_pool))
            if "{{RANDOM_AI_MODEL}}" in value:
                value = value.replace("{{RANDOM_AI_MODEL}}", random.choice(self.ai_model_pool))
            if "{{RANDOM_GUID}}" in value:
                value = value.replace("{{RANDOM_GUID}}", str(uuid.uuid4()))
            if "{{RANDOM_PID}}" in value:
                value = value.replace("{{RANDOM_PID}}", str(random.randint(1000, 65535)))
            if "{{RANDOM_PORT}}" in value:
                value = value.replace("{{RANDOM_PORT}}", str(random.randint(49152, 65535)))
            if "{{RANDOM_INT}}" in value:
                value = value.replace("{{RANDOM_INT}}", str(random.randint(100000, 999999)))
            
        elif isinstance(value, dict):
            return {k: self.resolve(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self.resolve(i) for i in value]
            
        return value
