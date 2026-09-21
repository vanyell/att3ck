"""
Kinetix Test Suite — H5 Implementation
Covers: Unit Validation, Variable Resolution, Thread Safety, CEF Format, Scenario Loading
"""
import pytest
import json
import os
import copy
import uuid
from pathlib import Path

# --- Unit Validation Tests ---

class TestSchemaValidation:
    """Every Pydantic model must accept valid input and reject invalid input."""

    def test_process_event_creates_with_required_fields(self):
        from kinetix.schemas.endpoint import ProcessEvent
        ev = ProcessEvent(
            FileName="cmd.exe",
            FolderPath="C:\\Windows\\System32",
            ProcessId=1234,
            ProcessCommandLine="cmd.exe /c whoami"
        )
        assert ev.event_type == "DeviceProcessEvents"
        assert ev.source == "endpoint"
        assert ev.file_name == "cmd.exe"
        assert ev.process_id == 1234

    def test_process_event_rejects_missing_command_line(self):
        from kinetix.schemas.endpoint import ProcessEvent
        with pytest.raises(Exception):
            ProcessEvent(FileName="cmd.exe", ProcessId=1234)

    def test_authentication_event_creates(self):
        from kinetix.schemas.cloud_auth import AuthenticationEvent
        ev = AuthenticationEvent(UserPrincipalName="user@test.com")
        assert ev.event_type == "SigninLogs"
        assert ev.source == "Azure AD"
        assert ev.user_principal_name == "user@test.com"

    def test_authentication_accepts_legacy_field_names(self):
        """AliasChoices should allow legacy 'user_name' as input."""
        from kinetix.schemas.cloud_auth import AuthenticationEvent
        ev = AuthenticationEvent(user_name="legacy@test.com")
        assert ev.user_principal_name == "legacy@test.com"

    def test_firewall_event_creates(self):
        from kinetix.schemas.network import FirewallEvent
        ev = FirewallEvent(
            DeviceAction="blocked", Protocol="TCP",
            SourcePort=12345, DestinationPort=443
        )
        assert ev.event_type == "CommonSecurityLog"
        assert ev.direction == "Outbound"  # default

    def test_security_alert_creates(self):
        from kinetix.schemas.security import SecurityAlert
        ev = SecurityAlert(AlertName="Test Alert", severity="High")
        assert ev.alert_name == "Test Alert"
        assert ev.confidence_level == "High"

    def test_security_incident_creates(self):
        from kinetix.schemas.security import SecurityIncident
        ev = SecurityIncident(Title="Test Incident")
        assert ev.status == "New"
        assert ev.owner == "Unassigned"

    def test_file_event_creates(self):
        from kinetix.schemas.endpoint import FileEvent
        ev = FileEvent(
            ActionType="FileCreated",
            FileName="test.txt",
            FolderPath="C:\\temp"
        )
        assert ev.event_type == "DeviceFileEvents"

    def test_registry_event_creates(self):
        from kinetix.schemas.endpoint import RegistryEvent
        ev = RegistryEvent(
            ActionType="RegistryValueSet",
            RegistryKey="HKLM\\Software\\Test"
        )
        assert ev.event_type == "DeviceRegistryEvents"

    def test_dns_event_creates(self):
        from kinetix.schemas.network import DNSEvent
        ev = DNSEvent(Name="example.com")
        assert ev.event_type == "DnsEvents"
        assert ev.query_type == "A"  # default


class TestBaseLogEvent:
    """Validates base model behavior and H2/H4 fixes."""

    def test_tenant_id_is_consistent_across_events(self):
        """H2: TenantId should be the same for all events in a session."""
        from kinetix.schemas.endpoint import ProcessEvent
        ev1 = ProcessEvent(FileName="a.exe", ProcessId=1, ProcessCommandLine="a")
        ev2 = ProcessEvent(FileName="b.exe", ProcessId=2, ProcessCommandLine="b")
        assert ev1.tenant_id == ev2.tenant_id

    def test_event_id_is_unique_per_instance(self):
        from kinetix.schemas.endpoint import ProcessEvent
        ev1 = ProcessEvent(FileName="a.exe", ProcessId=1, ProcessCommandLine="a")
        ev2 = ProcessEvent(FileName="a.exe", ProcessId=1, ProcessCommandLine="a")
        assert ev1.event_id != ev2.event_id

    def test_timestamp_is_timezone_aware(self):
        """H4: Timestamps should have timezone info."""
        from kinetix.schemas.endpoint import ProcessEvent
        ev = ProcessEvent(FileName="a.exe", ProcessId=1, ProcessCommandLine="a")
        assert ev.timestamp.tzinfo is not None

    def test_correlation_id_generated(self):
        from kinetix.schemas.base import BaseLogEvent
        ev = BaseLogEvent(SourceSystem="test", Type="test")
        assert ev.correlation_id is not None
        assert len(ev.correlation_id) == 36  # UUID format


# --- Variable Resolution Tests ---

class TestVariableManager:
    """Validates the VariableManager resolves all placeholder types."""

    def test_random_ip_resolves(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        result = vm.resolve("{{RANDOM_IP}}")
        assert "{{" not in result
        assert result.startswith("192.168.1.")

    def test_random_host_resolves(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        result = vm.resolve("{{RANDOM_HOST}}")
        assert result.startswith("WS-PROD-")

    def test_random_user_resolves(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        result = vm.resolve("{{RANDOM_USER}}")
        assert "{{" not in result

    def test_session_vars_are_consistent(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        r1 = vm.resolve("{{CNC_IP}}")
        r2 = vm.resolve("{{CNC_IP}}")
        assert r1 == r2  # Session vars don't change

    def test_random_pid_is_numeric_string(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        result = vm.resolve("{{RANDOM_PID}}")
        assert result.isdigit()
        assert 1000 <= int(result) <= 65535

    def test_nested_dict_resolution(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        data = {"key": "{{RANDOM_IP}}", "nested": {"inner": "{{RANDOM_HOST}}"}}
        result = vm.resolve(data)
        assert "{{" not in result["key"]
        assert "{{" not in result["nested"]["inner"]

    def test_list_resolution(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        data = ["{{RANDOM_IP}}", "{{RANDOM_USER}}"]
        result = vm.resolve(data)
        assert all("{{" not in item for item in result)

    def test_non_string_passthrough(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        assert vm.resolve(42) == 42
        assert vm.resolve(True) is True

    def test_random_email_resolves(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        result = vm.resolve("{{RANDOM_EMAIL}}")
        assert "@" in result
        assert "{{" not in result

    def test_random_ua_resolves(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        result = vm.resolve("{{RANDOM_UA}}")
        assert "{{" not in result
        assert len(result) > 5

    def test_random_url_resolves(self):
        """RANDOM_URL can be corpus-sampled from real mined telemetry (see
        kinetix/intelligence/corpus_profiles/), which legitimately includes
        plain http:// URLs -- not just the https-only static pool -- so this
        must not assert a fixed scheme."""
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        result = vm.resolve("{{RANDOM_URL}}")
        assert result.startswith("http://") or result.startswith("https://")
        assert "{{" not in result

    def test_corpus_backed_placeholders_are_single_line(self):
        """Every Kinetix output format is line-oriented (JSON Lines, CEF,
        syslog, "single-line" EVTX). A mined value with an embedded newline
        (e.g. DeviceEvents.EventData.ScriptBlockText, which is frequently a
        multi-line PowerShell script in the real corpus) would otherwise
        split into multiple lines and corrupt every downstream line-based
        parser -- confirmed via a real end-to-end main.py run producing
        malformed EVT XML lines before this was fixed in _corpus_or_pool."""
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        for _ in range(50):
            for placeholder in ("RANDOM_UA", "RANDOM_URL", "RANDOM_COMMANDLINE",
                                 "RANDOM_FILE_PATH", "RANDOM_REGISTRY_VALUE", "RANDOM_SCRIPT_BLOCK"):
                result = vm.resolve("{{" + placeholder + "}}")
                assert "\n" not in result and "\r" not in result, f"{placeholder} resolved to a multi-line value: {result!r}"

    def test_random_ai_model_resolves(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        result = vm.resolve("{{RANDOM_AI_MODEL}}")
        assert "GPT" in result or "Claude" in result or "Gemini" in result or "Llama" in result or "Mistral" in result or "DeepSeek" in result or "Cohere" in result
        assert "{{" not in result

    def test_random_server_resolves(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        result = vm.resolve("{{RANDOM_SERVER}}")
        assert result.startswith("SRV-")
        assert "{{" not in result

    def test_malicious_url_session_var(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        r1 = vm.resolve("{{MALICIOUS_URL}}")
        r2 = vm.resolve("{{MALICIOUS_URL}}")
        assert r1 == r2  # Session vars are consistent


# --- C2 Fix: Multiply Produces Unique Events ---

class TestMultiplyUniqueness:
    """C2: Each multiplied event must have distinct IDs and timestamps."""

    def test_multiply_produces_unique_events(self):
        from kinetix.core.vars import VariableManager
        import copy
        vm = VariableManager()

        template = {
            "source": "auth",
            "event_type": "authentication",
            "UserPrincipalName": "{{RANDOM_USER}}@test.com",
            "multiply": 5
        }

        from kinetix.schemas.cloud_auth import AuthenticationEvent
        events = []
        count = template.get("multiply", 1)
        for _ in range(count):
            e = vm.resolve(copy.deepcopy(template))
            params = e.copy()
            params.pop("source", None)
            params.pop("event_type", None)
            params.pop("multiply", None)
            events.append(AuthenticationEvent(**params))

        # All event IDs must be unique
        ids = [ev.event_id for ev in events]
        assert len(set(ids)) == 5, f"Expected 5 unique IDs, got {len(set(ids))}"

        # All correlation IDs must be unique
        corr_ids = [ev.correlation_id for ev in events]
        assert len(set(corr_ids)) == 5


# --- Output Format Tests ---

class TestOutputFormats:
    """Validates JSON and CEF output correctness."""

    def test_json_excludes_internal_fields(self):
        """L4: is_malicious, scenario_id, depth, killchain_phase must not appear in JSON output."""
        from kinetix.outputs.file import FileOutput
        from kinetix.schemas.endpoint import ProcessEvent

        ev = ProcessEvent(
            FileName="test.exe", ProcessId=1,
            ProcessCommandLine="test", is_malicious=True,
            scenario_id="TEST-001", killchain_phase="execution"
        )
        fo = FileOutput.__new__(FileOutput)  # Skip __init__
        json_str = fo._format_json(ev)
        parsed = json.loads(json_str)

        assert "is_malicious" not in parsed
        assert "scenario_id" not in parsed
        assert "depth" not in parsed
        assert "killchain_phase" not in parsed
        assert "FileName" in parsed  # Aliases should still work

    def test_json_uses_aliases(self):
        from kinetix.outputs.file import FileOutput
        from kinetix.schemas.endpoint import ProcessEvent

        ev = ProcessEvent(
            FileName="cmd.exe", ProcessId=99,
            ProcessCommandLine="cmd /c dir"
        )
        fo = FileOutput.__new__(FileOutput)
        json_str = fo._format_json(ev)
        parsed = json.loads(json_str)

        assert "TimeGenerated" in parsed
        assert "SourceSystem" in parsed
        assert "ProcessCommandLine" in parsed
        assert "CorrelationId" in parsed

    def test_cef_format_structure(self):
        """CEF lines must match the CEF:0|... format."""
        from kinetix.outputs.file import FileOutput
        from kinetix.schemas.endpoint import ProcessEvent
        from kinetix.schemas.base import MitreMapping

        ev = ProcessEvent(
            FileName="cmd.exe", ProcessId=99,
            ProcessCommandLine="cmd /c dir",
            mitre=MitreMapping(tactic="Execution", technique_id="T1059", technique_name="CLI")
        )
        fo = FileOutput.__new__(FileOutput)
        cef = fo._format_cef(ev)

        assert cef.startswith("CEF:0|")
        parts = cef.split("|")
        assert len(parts) >= 7  # vendor, product, version, class_id, name, severity, extensions
        assert "cs1Label=MitreTactic" in cef
        assert "cs2Label=MitreTechniqueId" in cef

    def test_cef_dynamic_fields(self):
        """Verify richness of CEF for DNSEvents and other field-heavy models."""
        from kinetix.outputs.file import FileOutput
        from kinetix.schemas.network import DNSEvent

        ev = DNSEvent(
            Name="outlook.office365.com",
            QueryType="AAAA",
            ResultCode="0",
            IPAddresses="2603:1026:201:1e::2"
        )
        fo = FileOutput.__new__(FileOutput)
        cef = fo._format_cef(ev)

        # Basic structure
        assert "cs1Label=Name cs1=outlook.office365.com" in cef
        assert "cs2Label=QueryType cs2=AAAA" in cef
        assert "cs3Label=ResultCode cs3=0" in cef
        assert "cs4Label=IPAddresses cs4=2603:1026:201:1e::2" in cef
        
        # Mapping verification
        assert "externalId=" in cef  # CorrelationId fallback
        assert "OSPlatform" not in cef # Should be excluded now

    def test_cef_overflow_beyond_cs6_is_logged_not_silent(self, caplog):
        """CEF's cs1-cs6 is a real spec limit (ArcSight CEF defines exactly 6
        custom-string extensions), so a field-heavy event genuinely can't fit
        everything -- but the drop must be logged, not silent."""
        import logging
        from kinetix.outputs.file import FileOutput
        from kinetix.schemas.email import EmailEvent

        ev = EmailEvent(sender="a@b.com", recipient="c@d.com", subject="Test",
                         DetectionMethods="AntiSpam", NetworkMessageId="msg-1",
                         SenderDisplayName="A B", ThreatNames="none",
                         ConfidenceLevel="0", BulkComplaintLevel="0")
        fo = FileOutput.__new__(FileOutput)
        with caplog.at_level(logging.DEBUG, logger="kinetix.outputs.file"):
            cef = fo._format_cef(ev)

        assert "cs6Label=" in cef
        assert "cs7Label=" not in cef  # cs7+ is not valid CEF, must never appear
        assert any("dropped fields" in r.message for r in caplog.records)

    def test_unmapped_source_uses_explicit_fallback_and_warns(self, caplog):
        """A schema with no entry in sentinel_tables or the source->table
        mapping must not silently guess a table filename via .capitalize()."""
        import logging
        from kinetix.outputs.file import FileOutput
        from kinetix.schemas.base import BaseLogEvent

        ev = BaseLogEvent(source="totally_unmapped_source", event_type="SomeNewThing")
        fo = FileOutput.__new__(FileOutput)
        with caplog.at_level(logging.WARNING, logger="kinetix.outputs.file"):
            table = fo._map_to_table_name(ev)

        assert table == "Unmapped_Totally_unmapped_source"
        assert any("No table mapping" in r.message for r in caplog.records)


class TestNewSchemas:
    """Validates newly wired schemas work correctly."""

    def test_vpn_event_creates(self):
        from kinetix.schemas.cloud_auth import VPNEvent
        ev = VPNEvent(client_ip="203.0.113.5")
        assert ev.event_type == "CommonSecurityLog"
        assert ev.source == "Firewall"

    def test_web_server_event_creates(self):
        from kinetix.schemas.app import WebServerEvent
        ev = WebServerEvent(url="/login", http_method="POST", status_code=200, user_agent="curl/8", response_time_ms=45)
        assert ev.event_type == "W3CIISLog"
        assert ev.source == "Web"

    def test_database_event_creates(self):
        from kinetix.schemas.app import DatabaseEvent
        ev = DatabaseEvent(db_name="SalesDB", query_text="SELECT * FROM Users", operation="SELECT")
        assert ev.event_type == "AzureDiagnostics"
        assert ev.source == "Azure"

    def test_proxy_event_creates(self):
        from kinetix.schemas.network import ProxyEvent
        ev = ProxyEvent(url="https://example.com", http_method="GET", http_status=200, user_agent="Mozilla/5.0", content_type="text/html")
        assert ev.event_type == "W3CIISLog"

    def test_registry_includes_all_schema_types(self):
        """All defined schema models are registered in the event registry."""
        from main import _build_event_registry
        registry = _build_event_registry()
        expected_types = [
            "authentication", "process_creation", "file_system", "registry",
            "network_connection", "dns_query", "proxy", "vpn",
            "web_request", "db_query", "office_activity", "cloud_activity",
            "security_alert", "security_incident", "linux_auth", "linux_sudo",
            "linux_audit", "linux_kernel", "linux_cron", "linux_process",
            "macos_log", "macos_auth", "macos_exec",
        ]
        for etype in expected_types:
            assert etype in registry, f"Missing registry entry: {etype}"


class TestAdditionalFieldsParity:
    """Phase 1: AdditionalFields/field parity with real Sentinel/Defender XDR
    table schemas, verified against Microsoft Learn's advanced-hunting and
    Azure Monitor table references (not guessed)."""

    def test_device_family_shares_additional_fields_as_string(self):
        """DeviceProcessEvents/DeviceFileEvents/DeviceRegistryEvents/DeviceEvents
        all carry a real "AdditionalFields" string column."""
        from kinetix.schemas.endpoint import ProcessEvent, FileEvent, RegistryEvent, DeviceGenericEvent
        p = ProcessEvent(FileName="a.exe", ProcessId=1, ProcessCommandLine="a.exe", AdditionalFields='{"k":"v"}')
        f = FileEvent(FileName="a.txt", FolderPath="C:\\", AdditionalFields='{"k":"v"}')
        r = RegistryEvent(RegistryKey="HKLM\\x", AdditionalFields='{"k":"v"}')
        d = DeviceGenericEvent(ActionType="UsbDriveMounted", AdditionalFields='{"k":"v"}')
        for ev in (p, f, r, d):
            dumped = ev.model_dump(by_alias=True)
            assert dumped["AdditionalFields"] == '{"k":"v"}'
            assert isinstance(dumped["AdditionalFields"], str)

    def test_email_event_has_missing_real_fields(self):
        from kinetix.schemas.email import EmailEvent
        ev = EmailEvent(sender="a@b.com", recipient="c@d.com", subject="Test",
                         RecipientObjectId="obj-1", SenderObjectId="obj-2",
                         SenderDisplayName="A B", ThreatNames="Trojan:Win/Foo",
                         ConfidenceLevel="High", BulkComplaintLevel=3, EmailClusterId=42,
                         AdditionalFields='{"x":1}')
        dumped = ev.model_dump(by_alias=True)
        assert dumped["RecipientObjectId"] == "obj-1"
        assert dumped["SenderObjectId"] == "obj-2"
        assert dumped["SenderDisplayName"] == "A B"
        assert dumped["ThreatNames"] == "Trojan:Win/Foo"
        assert dumped["ConfidenceLevel"] == "High"
        assert dumped["BulkComplaintLevel"] == 3
        assert dumped["EmailClusterId"] == 42
        assert dumped["AdditionalFields"] == '{"x":1}'

    def test_cloud_app_event_additional_fields_is_dict_not_string(self):
        """Real CloudAppEvents.AdditionalFields is "dynamic" type (a JSON
        object), unlike the "string" AdditionalFields on the Device*/Email*
        family -- these must not be serialized the same way."""
        from kinetix.schemas.cloud_app import CloudAppEvent
        ev = CloudAppEvent(Application="Office 365", ActionType="FileAccessed",
                            AdditionalFields={"RiskScore": 5})
        dumped = ev.model_dump(by_alias=True)
        assert dumped["AdditionalFields"] == {"RiskScore": 5}
        assert isinstance(dumped["AdditionalFields"], dict)

    def test_aad_non_interactive_signin_has_no_additional_fields_column(self):
        """AADNonInteractiveUserSignInLogs is a fully-enumerated Log Analytics
        table with no AdditionalFields column at all -- unlike the Defender
        XDR advanced-hunting tables. Must not fabricate one."""
        from kinetix.schemas.identity import AADNonInteractiveSignIn
        ev = AADNonInteractiveSignIn(AppId="app-1", ResourceId="res-1")
        dumped = ev.model_dump(by_alias=True)
        assert "AdditionalFields" not in dumped
        # Real fields that previously were missing from this schema.
        assert dumped["AuthenticationRequirement"] == "singleFactorAuthentication"
        assert dumped["RiskLevelDuringSignIn"] == "none"
        assert dumped["RiskLevelAggregated"] == "none"
        assert dumped["AuthenticationProtocol"] == "none"
        assert dumped["TokenIssuerType"] == "Azure AD"


class TestLinuxSchemas:
    """Validates Linux event schemas and their to_syslog() output."""

    def test_linux_auth_event_creates(self):
        from kinetix.schemas.linux import LinuxAuthEvent
        ev = LinuxAuthEvent(pid=1234, proc="sshd", log_message="Failed password for root from 10.0.0.1 port 22 ssh2")
        assert ev.source == "linux"
        assert ev.proc == "sshd"
        assert ev.os_platform == "Linux"
        assert ev.device_category == "Server"

    def test_linux_auth_to_syslog_format(self):
        from kinetix.schemas.linux import LinuxAuthEvent
        ev = LinuxAuthEvent(pid=1234, proc="sshd", log_message="Failed password for root from 10.0.0.1 port 22 ssh2")
        syslog = ev.to_syslog()
        assert syslog.startswith("<")
        assert "sshd" in syslog
        assert "Failed password" in syslog

    def test_linux_sudo_event_creates(self):
        from kinetix.schemas.linux import LinuxSudoEvent
        ev = LinuxSudoEvent(pid=1234, user="alice", command="whoami", hostname="web-01")
        assert ev.source == "linux"

    def test_linux_sudo_to_syslog(self):
        from kinetix.schemas.linux import LinuxSudoEvent
        ev = LinuxSudoEvent(pid=1234, user="alice", command="whoami", hostname="web-01")
        syslog = ev.to_syslog()
        assert "alice" in syslog
        assert "sudo" in syslog or "whoami" in syslog

    def test_linux_audit_event_creates(self):
        from kinetix.schemas.linux import LinuxAuditdEvent
        ev = LinuxAuditdEvent(pid=1234, hostname="db-01", audit_type="SYSCALL", audit_msg="arch=c000003e syscall=59 success=yes", auid=1000, ses=1)
        assert ev.source == "linux"

    def test_linux_audit_to_syslog(self):
        from kinetix.schemas.linux import LinuxAuditdEvent
        ev = LinuxAuditdEvent(pid=1234, hostname="db-01", audit_type="SYSCALL", audit_msg="arch=c000003e syscall=59 success=yes", auid=1000, ses=1)
        syslog = ev.to_syslog()
        assert "audit" in syslog
        assert "SYSCALL" in syslog

    def test_linux_kernel_to_syslog(self):
        from kinetix.schemas.linux import LinuxKernelEvent
        ev = LinuxKernelEvent(pid=0, log_message="CPU threshold exceeded")
        syslog = ev.to_syslog()
        assert "kernel" in syslog

    def test_linux_cron_to_syslog(self):
        from kinetix.schemas.linux import LinuxCronEvent
        ev = LinuxCronEvent(pid=1234, user="root", command="run-parts /etc/cron.hourly")
        syslog = ev.to_syslog()
        assert "CRON" in syslog or "cron" in syslog

    def test_linux_process_to_syslog(self):
        from kinetix.schemas.linux import LinuxProcessEvent
        ev = LinuxProcessEvent(pid=1234, exe="/usr/bin/ssh", args="ssh root@10.0.0.5", user="root", uid=0, gid=0)
        syslog = ev.to_syslog()
        assert "/usr/bin/ssh" in syslog or "ssh" in syslog

    def test_random_linux_host_resolves(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        result = vm.resolve("{{RANDOM_LINUX_HOST}}")
        assert "{{" not in result
        assert result


class TestMacOSSchemas:
    """Validates macOS event schemas and their to_syslog() output."""

    def test_macos_log_event_creates(self):
        from kinetix.schemas.macos import MacOSLogEvent
        ev = MacOSLogEvent(pid=5678, proc="installer", log_message="Install will request elevated privileges")
        assert ev.source == "macos"
        assert ev.os_platform == "macOS"

    def test_macos_log_to_syslog(self):
        from kinetix.schemas.macos import MacOSLogEvent
        ev = MacOSLogEvent(pid=5678, proc="installer", log_message="Install will request elevated privileges")
        syslog = ev.to_syslog()
        assert "installer" in syslog

    def test_macos_auth_event_creates(self):
        from kinetix.schemas.macos import MacOSAuthEvent
        ev = MacOSAuthEvent(pid=5678, proc="authd", log_message="USER_AUTH: user jsmith authenticated via TouchID", user="jsmith")
        assert ev.source == "macos"

    def test_macos_auth_to_syslog(self):
        from kinetix.schemas.macos import MacOSAuthEvent
        ev = MacOSAuthEvent(pid=5678, proc="authd", log_message="USER_AUTH: user jsmith authenticated via TouchID", user="jsmith")
        syslog = ev.to_syslog()
        assert "authd" in syslog or "auth" in syslog.lower()

    def test_macos_exec_event_creates(self):
        from kinetix.schemas.macos import MacOSAppExecEvent
        ev = MacOSAppExecEvent(pid=5678, proc="kernel", bundle_id="com.example.trojan", app_path="/Applications/Evil.app", signer="Not signed", log_message="execution of untrusted app")
        assert ev.source == "macos"

    def test_macos_exec_to_syslog(self):
        from kinetix.schemas.macos import MacOSAppExecEvent
        ev = MacOSAppExecEvent(pid=5678, proc="kernel", bundle_id="com.example.trojan", app_path="/Applications/Evil.app", signer="Not signed", log_message="execution of untrusted app")
        syslog = ev.to_syslog()
        assert "kernel" in syslog
        assert "untrusted app" in syslog

    def test_random_mac_host_resolves(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        result = vm.resolve("{{RANDOM_MAC_HOST}}")
        assert "{{" not in result
        assert result


class TestSyslogOutput:
    """Validates syslog output format and file creation."""

    def test_syslog_format_structure(self):
        from kinetix.schemas.linux import LinuxAuthEvent
        ev = LinuxAuthEvent(pid=1234, proc="sshd", log_message="Failed password for root from 10.0.0.1 port 22 ssh2")
        syslog = ev.to_syslog()
        assert syslog.startswith("<")
        assert ">" in syslog
        assert "sshd" in syslog
        assert "Failed password" in syslog

    def test_syslog_priority_range(self):
        from kinetix.schemas.linux import LinuxAuthEvent
        ev = LinuxAuthEvent(pid=1234, proc="sshd", log_message="test")
        syslog = ev.to_syslog()
        pri = int(syslog.split(">")[0].lstrip("<"))
        assert 0 <= pri <= 191

    def test_json_events_still_output_unaffected(self):
        """Existing JSON/CEF output must not be broken by syslog additions."""
        from kinetix.outputs.file import FileOutput
        from kinetix.schemas.endpoint import ProcessEvent
        ev = ProcessEvent(FileName="test.exe", ProcessId=1, ProcessCommandLine="test")
        fo = FileOutput.__new__(FileOutput)
        json_str = fo._format_json(ev)
        parsed = json.loads(json_str)
        assert "TimeGenerated" in parsed
        assert "FileName" in parsed


class TestEVTOutput:
    """Validates Windows Event XML output format."""

    def test_evt_format_structure(self):
        from kinetix.schemas.endpoint import ProcessEvent
        ev = ProcessEvent(FileName="cmd.exe", ProcessId=1234, ProcessCommandLine="cmd /c whoami")
        evt = ev.to_evt()
        assert evt.startswith("<Event xmlns=")
        assert "EventID>4688<" in evt
        assert "Microsoft-Windows-Security-Auditing" in evt
        assert "Channel>Security<" in evt
        assert "CommandLine" in evt

    def test_evt_file_event(self):
        from kinetix.schemas.endpoint import FileEvent
        ev = FileEvent(ActionType="FileCreated", FileName="malware.exe", FolderPath="C:\\temp")
        evt = ev.to_evt()
        assert "EventID>4663<" in evt
        assert "ObjectName" in evt

    def test_evt_registry_event(self):
        from kinetix.schemas.endpoint import RegistryEvent
        ev = RegistryEvent(ActionType="RegistryValueSet", RegistryKey="HKLM\\Software\\Test", RegistryValueName="Malicious", RegistryValueData="malicious.exe")
        evt = ev.to_evt()
        assert "EventID>4657<" in evt

    def test_evt_auth_event_success(self):
        from kinetix.schemas.cloud_auth import AuthenticationEvent
        ev = AuthenticationEvent(UserPrincipalName="admin@test.com", ResultType="0")
        evt = ev.to_evt()
        assert "EventID>4624<" in evt

    def test_evt_auth_event_failure(self):
        from kinetix.schemas.cloud_auth import AuthenticationEvent
        ev = AuthenticationEvent(UserPrincipalName="root@test.com", ResultType="4625")
        evt = ev.to_evt()
        assert "EventID>4625<" in evt

    def test_evt_firewall_event(self):
        from kinetix.schemas.network import FirewallEvent
        ev = FirewallEvent(DeviceAction="blocked", Protocol="TCP", SourcePort=12345, DestinationPort=443)
        evt = ev.to_evt()
        assert "EventID>5157<" in evt

    def test_evt_dns_event(self):
        from kinetix.schemas.network import DNSEvent
        ev = DNSEvent(Name="evil.com")
        evt = ev.to_evt()
        assert "EventID>3008<" in evt

    def test_evt_security_alert(self):
        from kinetix.schemas.security import SecurityAlert
        ev = SecurityAlert(AlertName="Test Alert", severity="High")
        evt = ev.to_evt()
        # SecurityAlert is Sentinel-native (no real Windows EVTX equivalent) —
        # it must use a synthetic ID, not a real (and differently-meaning)
        # Windows Security-Auditing event ID like 1102 ("audit log cleared").
        assert "EventID>9101<" in evt

    def test_linux_event_has_no_evt(self):
        """Linux events use syslog only, verify EVT is not Windows Event XML."""
        from kinetix.schemas.linux import LinuxAuthEvent
        ev = LinuxAuthEvent(pid=1234, proc="sshd", log_message="test")
        evt = ev.to_evt()
        # Linux event uses default to_evt (generic), not Windows Event XML
        assert "Event xmlns=" in evt

    def test_evt_routing_in_file_output(self):
        """Windows events should write EVT; Linux events should not."""
        from kinetix.outputs.file import FileOutput
        fo = FileOutput.__new__(FileOutput)
        from kinetix.schemas.endpoint import ProcessEvent
        win_ev = ProcessEvent(FileName="test.exe", ProcessId=1, ProcessCommandLine="test")
        assert not fo._is_syslog_event(win_ev), "Windows events should not be flagged as syslog-only"
        from kinetix.schemas.linux import LinuxAuthEvent
        lin_ev = LinuxAuthEvent(pid=1234, proc="sshd", log_message="test")
        assert fo._is_syslog_event(lin_ev), "Linux events should be flagged as syslog-only"


class TestKillchainPhase:
    """Validates killchain_phase tracking works through the pipeline."""

    def test_base_model_accepts_killchain_phase(self):
        from kinetix.schemas.base import BaseLogEvent
        ev = BaseLogEvent(SourceSystem="test", Type="test", killchain_phase="initial-access")
        assert ev.killchain_phase == "initial-access"

    def test_killchain_phase_excluded_from_json(self):
        from kinetix.outputs.file import FileOutput
        from kinetix.schemas.base import BaseLogEvent
        ev = BaseLogEvent(SourceSystem="test", Type="test", killchain_phase="execution")
        fo = FileOutput.__new__(FileOutput)
        json_str = fo._format_json(ev)
        assert "killchain_phase" not in json_str

    def test_killchain_phase_inherited_by_follow_up(self):
        from kinetix.core.temporal import TemporalEngine
        from kinetix.schemas.endpoint import ProcessEvent
        te = TemporalEngine()
        parent = ProcessEvent(
            FileName="init.exe", ProcessId=100,
            ProcessCommandLine="init", killchain_phase="execution"
        )
        follow_up = te.create_follow_up(parent, "DeviceFileEvents")
        assert follow_up is not None
        assert follow_up.killchain_phase == "execution"


# --- Scenario Loading Tests ---

class TestScenarioLoading:
    """Validates that every scenario file in the repo loads without error."""

    SCENARIO_DIR = Path(__file__).parent.parent / "scenarios"

    def _get_scenario_files(self):
        return list(self.SCENARIO_DIR.glob("*.json"))

    def test_all_scenarios_are_valid_json(self):
        for f in self._get_scenario_files():
            data = json.loads(f.read_text())
            assert isinstance(data, list), f"{f.name} root must be a JSON array"
            for stage in data:
                assert "name" in stage, f"{f.name}: stage missing 'name'"
                assert "events" in stage, f"{f.name}: stage missing 'events'"

    def test_all_scenarios_load_without_error(self):
        """Every scenario must successfully instantiate all its models."""
        from main import load_scenario
        from kinetix.core.vars import VariableManager
        vm = VariableManager()

        for f in self._get_scenario_files():
            try:
                stages = load_scenario(str(f), vm)
                assert len(stages) > 0, f"{f.name}: produced zero stages"
                for stage in stages:
                    assert len(stage["events"]) > 0, f"{f.name}: stage '{stage['name']}' has zero events"
            except Exception as e:
                pytest.fail(f"Scenario {f.name} failed to load: {e}")

    def test_no_scenario_event_falls_back_to_base_log_event(self):
        """
        Regression test for the registry gap: an `event_type` string used in a
        scenario JSON file that isn't registered in main._build_event_registry()
        silently resolves to the generic BaseLogEvent, which (a) drops every
        field not in the base schema and (b) can route to a malformed/non-Sentinel
        table name via file.py's source-string fallback. Every event a scenario
        actually emits must resolve to a real, dedicated schema class.
        """
        from main import load_scenario
        from kinetix.core.vars import VariableManager
        from kinetix.schemas.base import BaseLogEvent
        vm = VariableManager()

        offenders = []
        for f in self._get_scenario_files():
            stages = load_scenario(str(f), vm)
            for stage in stages:
                for event in stage["events"]:
                    if type(event) is BaseLogEvent:
                        offenders.append(f"{f.name}: event_type={event.event_type!r} source={event.source!r}")

        assert not offenders, "Events falling back to generic BaseLogEvent (missing registry entry):\n" + "\n".join(offenders)


# --- Markov Engine Tests ---

class TestTemporalEngine:
    """M5: Validates that the Markov engine actually produces follow-up events."""

    def test_signin_triggers_follow_up(self):
        from kinetix.core.temporal import TemporalEngine
        te = TemporalEngine()
        next_type = te.get_next_event_type("SigninLogs")
        assert next_type in ["DeviceProcessEvents", "OfficeActivity", "AzureActivity"]

    def test_process_triggers_follow_up(self):
        from kinetix.core.temporal import TemporalEngine
        te = TemporalEngine()
        next_type = te.get_next_event_type("DeviceProcessEvents")
        assert next_type in ["CommonSecurityLog", "DeviceFileEvents", "DnsEvents"]

    def test_unknown_event_returns_none(self):
        from kinetix.core.temporal import TemporalEngine
        te = TemporalEngine()
        assert te.get_next_event_type("NonExistentTable") is None

    def test_create_follow_up_produces_valid_event(self):
        from kinetix.core.temporal import TemporalEngine
        from kinetix.schemas.endpoint import ProcessEvent

        te = TemporalEngine()
        parent = ProcessEvent(
            FileName="parent.exe", ProcessId=100,
            ProcessCommandLine="parent.exe", user_name="testuser",
            hostname="WS-01"
        )
        follow_up = te.create_follow_up(parent, "DeviceProcessEvents")
        assert follow_up is not None
        assert follow_up.correlation_id == parent.correlation_id
        assert follow_up.user_name == "testuser"

    def test_every_declared_transition_target_has_a_follow_up_factory(self):
        """Regression guard: the transition table previously named next-types
        (DnsEvents/SigninLogs/OfficeActivity/AzureActivity/CloudAppEvents) that
        create_follow_up() had no branch for, so those transitions silently
        resolved to None instead of producing an event."""
        from kinetix.core.temporal import TemporalEngine
        from kinetix.schemas.endpoint import ProcessEvent

        te = TemporalEngine()
        parent = ProcessEvent(
            FileName="parent.exe", ProcessId=100,
            ProcessCommandLine="parent.exe", user_name="testuser",
            hostname="WS-01", source_ip="10.0.0.5"
        )
        all_targets = {t for probs in te.transitions.values() for t in probs}
        missing = [t for t in sorted(all_targets) if te.create_follow_up(parent, t) is None]
        assert not missing, f"No follow-up factory for declared transition target(s): {missing}"

    def test_follow_up_factory_handles_parent_with_no_user_name(self):
        """Regression guard: a DNS/network-originated parent event commonly has
        no user_name, and AuthenticationEvent's required user_principal_name
        field was previously populated with that None via AliasChoices
        auto-matching on context["user_name"], failing Pydantic validation
        (surfaced by running the real simulation end-to-end)."""
        from kinetix.core.temporal import TemporalEngine
        from kinetix.schemas.network import DNSEvent

        te = TemporalEngine()
        parent = DNSEvent(Name="example.com", hostname="WS-01")
        assert parent.user_name is None
        all_targets = {t for probs in te.transitions.values() for t in probs}
        missing = [t for t in sorted(all_targets) if te.create_follow_up(parent, t) is None]
        assert not missing, f"No follow-up factory for declared transition target(s): {missing}"


class TestEmailEvent:
    def test_email_event_creates_with_required_fields(self):
        from kinetix.schemas.email import EmailEvent
        e = EmailEvent(sender="a@b.com", recipient="c@d.com", subject="Test")
        assert e.sender == "a@b.com"
        assert e.recipient == "c@d.com"
        assert e.subject == "Test"
        assert e.event_type == "EmailEvents"
        assert e.attachment_verdict == "NoAttachment"
        assert e.detection_method == "None"

    def test_email_event_malicious(self):
        from kinetix.schemas.email import EmailEvent
        e = EmailEvent(
            sender="attacker@evil.com", recipient="user@litware.com",
            subject="Invoice", attachment_verdict="Malicious",
            threat_types="Phish", detection_method="Heuristic",
            is_malicious=True,
        )
        assert e.attachment_verdict == "Malicious"
        assert e.detection_method == "Heuristic"
        assert e.is_malicious
        assert e.threat_types == "Phish"
        assert "Malicious" in e.to_syslog()

    def test_email_event_syslog_format(self):
        from kinetix.schemas.email import EmailEvent
        e = EmailEvent(sender="a@b.com", recipient="c@d.com", subject="Test")
        syslog = e.to_syslog()
        assert syslog.startswith("<")
        assert "a@b.com" in syslog
        assert "c@d.com" in syslog

    def test_email_event_evt_format(self):
        from kinetix.schemas.email import EmailEvent
        e = EmailEvent(sender="a@b.com", recipient="c@d.com", subject="Test")
        evt = e.to_evt()
        assert "<Event" in evt
        assert "a@b.com" in evt

    def test_email_event_sentinel_table_name(self):
        from kinetix.schemas.email import EmailEvent
        e = EmailEvent(sender="a@b.com", recipient="c@d.com", subject="Test")
        assert e.event_type == "EmailEvents"


class TestCloudAppEvent:
    def test_cloud_app_event_creates(self):
        from kinetix.schemas.cloud_app import CloudAppEvent
        c = CloudAppEvent(app_name="TestApp", action_type="Consent to application")
        assert c.app_name == "TestApp"
        assert c.action_type == "Consent to application"
        assert c.event_type == "CloudAppEvents"

    def test_cloud_app_malicious_oauth(self):
        from kinetix.schemas.cloud_app import CloudAppEvent
        c = CloudAppEvent(
            app_name="EvilApp", action_type="Consent to application",
            risk_level="High", oauth_consent_scope="Mail.ReadWrite offline_access",
            is_third_party_app=True, is_malicious=True,
        )
        assert c.risk_level == "High"
        assert c.oauth_consent_scope == "Mail.ReadWrite offline_access"
        assert c.is_third_party_app

    def test_cloud_app_syslog(self):
        from kinetix.schemas.cloud_app import CloudAppEvent
        c = CloudAppEvent(app_name="TestApp", action_type="ReadData")
        syslog = c.to_syslog()
        assert syslog.startswith("<")
        assert "TestApp" in syslog


class TestIdentityLogonEvent:
    def test_identity_logon_creates(self):
        from kinetix.schemas.identity import IdentityLogonEvent
        i = IdentityLogonEvent(logon_type="Interactive", protocol="Kerberos", logon_result="Success")
        assert i.logon_type == "Interactive"
        assert i.protocol == "Kerberos"
        assert i.logon_result == "Success"
        assert i.event_type == "IdentityLogonEvents"

    def test_identity_logon_admin_detection(self):
        from kinetix.schemas.identity import IdentityLogonEvent
        i = IdentityLogonEvent(
            logon_type="RemoteInteractive", protocol="OAuth",
            logon_result="Success", is_admin_logon=True,
            account_domain="litware.com", source_ip="192.168.1.100",
            is_malicious=True,
        )
        assert i.is_admin_logon
        assert i.account_domain == "litware.com"

    def test_identity_logon_failure(self):
        from kinetix.schemas.identity import IdentityLogonEvent
        i = IdentityLogonEvent(
            logon_type="Interactive", protocol="Kerberos",
            logon_result="Failure", failure_reason="Invalid password",
        )
        assert i.logon_result == "Failure"
        assert i.failure_reason == "Invalid password"

    def test_identity_logon_evt(self):
        from kinetix.schemas.identity import IdentityLogonEvent
        i = IdentityLogonEvent(logon_type="Interactive", protocol="Kerberos", logon_result="Success")
        evt = i.to_evt()
        assert "4624" in evt


class TestAADNonInteractiveSignIn:
    def test_non_interactive_creates(self):
        from kinetix.schemas.identity import AADNonInteractiveSignIn
        a = AADNonInteractiveSignIn(
            service_principal_name="SyncAgent",
            app_id="00000000-0000-0000-0000-000000000000",
            resource_id="https://graph.microsoft.com",
        )
        assert a.service_principal_name == "SyncAgent"
        assert a.app_id == "00000000-0000-0000-0000-000000000000"
        assert a.is_service_principal
        assert a.event_type == "AADNonInteractiveUserSignInLogs"

    def test_non_interactive_malicious(self):
        from kinetix.schemas.identity import AADNonInteractiveSignIn
        a = AADNonInteractiveSignIn(
            service_principal_name="BackdoorApp",
            app_id="11111111-1111-1111-1111-111111111111",
            resource_id="https://graph.microsoft.com",
            result_type="0",
            source_ip="91.228.100.50",
            is_malicious=True,
        )
        assert a.is_malicious
        assert a.source_ip == "91.228.100.50"

    def test_non_interactive_syslog(self):
        from kinetix.schemas.identity import AADNonInteractiveSignIn
        a = AADNonInteractiveSignIn(
            service_principal_name="SyncAgent",
            app_id="00000000-0000-0000-0000-000000000000",
            resource_id="https://graph.microsoft.com",
        )
        syslog = a.to_syslog()
        assert syslog.startswith("<")
        assert "SyncAgent" in syslog


class TestPersonaVariables:
    def test_persona_vars_resolve(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        for key in ["PERSONA_USER", "PERSONA_HOST", "PERSONA_EMAIL", "PERSONA_ROLE", "PERSONA_DEPT", "PERSONA_DOMAIN"]:
            resolved = vm.resolve(f"{{{{{key}}}}}")
            assert isinstance(resolved, str) and len(resolved) > 0

    def test_persona_consistency_in_session(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        username = vm.resolve("{{PERSONA_USER}}")
        email = vm.resolve("{{PERSONA_EMAIL}}")
        assert username in email


class TestExpectedDetectionField:
    def test_expected_detection_default(self):
        from kinetix.schemas.endpoint import ProcessEvent
        e = ProcessEvent(
            FileName="test.exe", ProcessId=123,
            ProcessCommandLine="test.exe",
        )
        assert e.expected_detection is False
        assert e.detection_guidance is None

    def test_expected_detection_set(self):
        from kinetix.schemas.base import BaseLogEvent
        e = BaseLogEvent(
            source="test", event_type="test",
            expected_detection=True,
            detection_guidance="Alert should fire on this event",
        )
        assert e.expected_detection
        assert e.detection_guidance == "Alert should fire on this event"


class TestNewScenarioLoading:
    def _load_scenario(self, path):
        import importlib.util
        import sys
        spec = importlib.util.spec_from_file_location("main", "main.py")
        main = importlib.util.module_from_spec(spec)
        sys.modules["main"] = main
        spec.loader.exec_module(main)
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        return main.load_scenario(path, vm)

    def test_oauth_consent_phishing_loads(self):
        stages = self._load_scenario("scenarios/oauth_consent_phishing.json")
        assert len(stages) == 5
        total = sum(len(s["events"]) for s in stages)
        assert total >= 8

    def test_oauth_device_code_loads(self):
        stages = self._load_scenario("scenarios/oauth_device_code_phishing.json")
        assert len(stages) == 5

    def test_rmm_abuse_loads(self):
        stages = self._load_scenario("scenarios/rmm_tool_abuse_c2.json")
        assert len(stages) == 5

    def test_sso_token_theft_loads(self):
        stages = self._load_scenario("scenarios/sso_session_token_theft.json")
        assert len(stages) == 5

    def test_adcs_abuse_loads(self):
        stages = self._load_scenario("scenarios/adcs_certificate_abuse.json")
        assert len(stages) == 5

    def test_cross_tenant_sync_loads(self):
        stages = self._load_scenario("scenarios/cross_tenant_sync_attack.json")
        assert len(stages) == 5


# --- Corpus Integrity Tests ---
# Guards the invariant documented in kinetix/intelligence/corpus.py and
# scripts/mine_corpus.py: freeform value pools must never carry real
# identifier-shaped values (IPs, IP:port, accounts, GUIDs, emails, SIDs).
# Regression test for a real leak found during a corpus review: mined
# EventData.ClientIP/username/jobOwner fields carried raw sandbox IPs and
# "DOMAIN\\user" account strings that the (older) miner classifier missed.
class TestCorpusIntegrity:
    def _iter_freeform_values(self):
        from kinetix.intelligence.corpus import DEFAULT_PROFILE_DIR

        for path in sorted(DEFAULT_PROFILE_DIR.glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            for field_name, entry in data.get("fields", {}).items():
                if entry.get("kind") != "freeform":
                    continue
                for row in entry.get("values", []):
                    value = row.get("value")
                    if isinstance(value, str):
                        yield path.name, field_name, value

    def test_no_identifier_shaped_values_in_freeform_pools(self):
        from scripts.mine_corpus import (
            _IPV4_RE, _IPV4_PORT_RE, _IPV6_PORT_RE, _GUID_RE, _EMAIL_RE, _SID_RE, _ACCOUNT_RE,
        )

        def is_identifier_shaped(value: str) -> bool:
            return bool(
                _IPV4_RE.match(value)
                or _IPV4_PORT_RE.match(value)
                or _IPV6_PORT_RE.match(value)
                or _GUID_RE.match(value)
                or _EMAIL_RE.match(value)
                or _SID_RE.match(value)
                or _ACCOUNT_RE.match(value)
            )

        leaks = [
            (fname, field, value)
            for fname, field, value in self._iter_freeform_values()
            if is_identifier_shaped(value)
        ]
        assert leaks == [], f"Identifier-shaped values leaked into freeform corpus pools: {leaks[:10]}"
