import random
import uuid

class VariableManager:
    """
    Handles dynamic placeholder replacement in scenario files.
    """
    def __init__(self):
        self._set_session_vars()
        self.ip_pool = [f"192.168.1.{i}" for i in range(10, 250)]
        self.host_pool = [f"WS-PROD-{i:03d}" for i in range(1, 100)]
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
            "ppeterson", "gbailey", "rreed", "hkelly", "khoward", "ramos", "jcox", "award"
        ]

    def _set_session_vars(self):
        self.session_vars = {
            "SESSION_ID": str(uuid.uuid4()),
            "CNC_IP": f"91.228.{random.randint(1,254)}.{random.randint(1,254)}",
            "MALICIOUS_DOMAIN": random.choice(["evil-cnc.net", "update-msft.com", "security-alert.io"])
        }

    def resolve(self, value: any) -> any:
        if isinstance(value, str):
            # 1. System/Session Templates
            for k, v in self.session_vars.items():
                value = value.replace(f"{{{{{k}}}}}", v)
            
            # 2. Random Generators
            if "{{RANDOM_IP}}" in value:
                value = value.replace("{{RANDOM_IP}}", random.choice(self.ip_pool))
            if "{{RANDOM_HOST}}" in value:
                value = value.replace("{{RANDOM_HOST}}", random.choice(self.host_pool))
            if "{{RANDOM_USER}}" in value:
                value = value.replace("{{RANDOM_USER}}", random.choice(self.user_pool))
            if "{{RANDOM_GUID}}" in value:
                value = value.replace("{{RANDOM_GUID}}", str(uuid.uuid4()))
            if "{{RANDOM_PID}}" in value:
                value = value.replace("{{RANDOM_PID}}", str(random.randint(1000, 65535)))
            if "{{RANDOM_PORT}}" in value:
                value = value.replace("{{RANDOM_PORT}}", str(random.randint(49152, 65535)))
            
        elif isinstance(value, dict):
            return {k: self.resolve(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self.resolve(i) for i in value]
            
        return value
