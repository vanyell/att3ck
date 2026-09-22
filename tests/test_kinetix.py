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
        assert any(result.startswith(subnet) for subnet in vm._ip_subnets)

    def test_random_host_resolves(self):
        from kinetix.core.vars import VariableManager
        vm = VariableManager()
        result = vm.resolve("{{RANDOM_HOST}}")
        assert result.startswith(("WS-SEA-", "WS-NYC-", "WS-LON-"))

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

    def test_evt_carries_timecreated(self):
        """decoder/windows-event/0 maps event.start from
        System.TimeCreated.@SystemTime. Without the element every indexed
        document falls back to ingest time, which silently voids --sim-clock
        backdating for this feed (measured: 0 of 75,434 indexed windows docs
        had event.start)."""
        from datetime import datetime, timezone
        from kinetix.schemas.endpoint import ProcessEvent
        ts = datetime(2026, 9, 1, 13, 45, 30, tzinfo=timezone.utc)
        ev = ProcessEvent(TimeGenerated=ts, FileName="cmd.exe", ProcessId=1,
                          ProcessCommandLine="cmd /c whoami")
        evt = ev.to_evt()
        assert "<TimeCreated SystemTime='2026-09-01T13:45:30.000Z'/>" in evt

    def test_evt_file_event_uses_sysmon_file_create(self):
        """4663 is on decoder/windows-event/0's discard list, so file activity
        shipped as 4663 is dropped by the engine no matter how well-formed it
        is (ingest-verified: 4 variants, including a fully Microsoft-faithful
        one, all produced 0 documents). Sysmon file events are not on that
        list and decode via decoder/windows-sysmon/0."""
        from kinetix.schemas.endpoint import FileEvent
        ev = FileEvent(ActionType="FileCreated", FileName="malware.exe", FolderPath="C:\\temp")
        evt = ev.to_evt()
        assert "EventID>11<" in evt
        assert "Provider Name='Microsoft-Windows-Sysmon'" in evt
        assert "Channel>Microsoft-Windows-Sysmon/Operational<" in evt
        assert "TargetFilename" in evt
        assert "C:\\temp\\malware.exe" in evt

    def test_evt_file_delete_uses_sysmon_file_delete(self):
        from kinetix.schemas.endpoint import FileEvent
        ev = FileEvent(ActionType="FileDeleted", FileName="evidence.log", FolderPath="C:\\logs")
        evt = ev.to_evt()
        assert "EventID>23<" in evt
        assert "Channel>Microsoft-Windows-Sysmon/Operational<" in evt

    def test_no_evt_event_id_is_on_the_wazuh_discard_list(self):
        """decoder/windows-event/0 carries the ruleset's only discard_events()
        block, keyed on these codes. An endpoint schema emitting one of them
        produces zero indexed documents on Wazuh 5.0, with no error anywhere.
        This guard covers every Windows-shaped schema Kinetix ships."""
        import re
        from kinetix.schemas.endpoint import ProcessEvent, FileEvent, RegistryEvent, DeviceGenericEvent
        from kinetix.schemas.network import FirewallEvent
        discarded = {"4656", "4658", "4660", "4663", "4670", "4690", "4703",
                     "4907", "5145", "5152", "5156", "5157", "5447"}
        events = [
            ProcessEvent(FileName="a.exe", ProcessId=1, ProcessCommandLine="a"),
            FileEvent(ActionType="FileCreated", FileName="a.txt", FolderPath="C:\\t"),
            FileEvent(ActionType="FileDeleted", FileName="a.txt", FolderPath="C:\\t"),
            RegistryEvent(ActionType="RegistryValueSet", RegistryKey="HKLM\\S",
                          RegistryValueName="V", RegistryValueData="d"),
            DeviceGenericEvent(ActionType="AntivirusDetection"),
            FirewallEvent(DeviceAction="blocked", Protocol="TCP", SourcePort=1, DestinationPort=443),
            FirewallEvent(DeviceAction="allowed", Protocol="TCP", SourcePort=1, DestinationPort=443),
        ]
        for ev in events:
            code = re.search(r"<EventID>(\d+)</EventID>", ev.to_evt()).group(1)
            assert code not in discarded, f"{type(ev).__name__} emits discarded code {code}"

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

    def test_evt_firewall_event_uses_sysmon_network_connect(self):
        """5156/5157 are on decoder/windows-event/0's discard list (both
        ingest-verified as 0 documents), so the Windows Filtering Platform
        codes never reach the index. Sysmon 3 does. The allow/block
        distinction Sysmon 3 has no field for is carried in RuleName."""
        from kinetix.schemas.network import FirewallEvent
        ev = FirewallEvent(DeviceAction="blocked", Protocol="TCP", SourcePort=12345, DestinationPort=443)
        evt = ev.to_evt()
        assert "EventID>3<" in evt
        assert "Provider Name='Microsoft-Windows-Sysmon'" in evt
        assert "Channel>Microsoft-Windows-Sysmon/Operational<" in evt
        assert "DestinationPort" in evt
        assert "RuleName" in evt and "blocked" in evt

    def test_evt_firewall_allowed_keeps_action_in_rulename(self):
        from kinetix.schemas.network import FirewallEvent
        ev = FirewallEvent(DeviceAction="allowed", Protocol="TCP", SourcePort=1, DestinationPort=80)
        evt = ev.to_evt()
        assert "EventID>3<" in evt
        assert "allowed" in evt

    def test_evt_dns_event(self):
        """DNS Server analytical (256), not DNS Client (3008) — see
        TestVendorFeeds for why the server channel is the one Wazuh decodes."""
        from kinetix.schemas.network import DNSEvent
        ev = DNSEvent(Name="evil.com")
        evt = ev.to_evt()
        assert "EventID>256<" in evt
        assert "Channel>Microsoft-Windows-DNSServer/Analytical<" in evt

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


class TestCalendarShaping:
    """Weekend shaping is meaningful on the simulated timeline, but on the
    real-time path it compounds with the after-hours divisor (0.1 * 0.15 = 66x)
    and throttles an ordinary `--duration 60` run down to a handful of events
    on a Saturday evening, with nothing in the output explaining why."""

    def _profile(self, **kwargs):
        from kinetix.schemas.temporal import TimingProfile
        # jitter_percent=0 makes calculate_delay() deterministic
        return TimingProfile(avg_delay_seconds=1.0, jitter_percent=0.0, **kwargs)

    def test_weekend_does_not_slow_delays_by_default(self):
        from datetime import datetime, timezone
        from kinetix.core.temporal import TemporalEngine

        te = TemporalEngine(profile=self._profile())
        saturday_evening = datetime(2026, 9, 19, 22, 0, tzinfo=timezone.utc)
        wednesday_evening = datetime(2026, 9, 16, 22, 0, tzinfo=timezone.utc)

        assert te.calculate_delay(saturday_evening) == pytest.approx(
            te.calculate_delay(wednesday_evening)
        )

    def test_weekend_slows_delays_when_calendar_shaping_enabled(self):
        from datetime import datetime, timezone
        from kinetix.core.temporal import TemporalEngine

        profile = self._profile(weekend_shaping=True)
        assert profile.weekend_shaping is True, "TimingProfile has no weekend_shaping switch"

        te = TemporalEngine(profile=profile)
        saturday_noon = datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc)
        wednesday_noon = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)

        # weekend_multiplier=0.15 -> weekend delays are 1/0.15 longer
        assert te.calculate_delay(saturday_noon) == pytest.approx(
            te.calculate_delay(wednesday_noon) / 0.15
        )

    def test_after_hours_shaping_still_applies_by_default(self):
        """Guard: gating the weekend divisor must not disable the diurnal curve."""
        from datetime import datetime, timezone
        from kinetix.core.temporal import TemporalEngine

        te = TemporalEngine(profile=self._profile())
        wednesday_noon = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
        wednesday_night = datetime(2026, 9, 16, 22, 0, tzinfo=timezone.utc)

        assert te.calculate_delay(wednesday_night) == pytest.approx(
            te.calculate_delay(wednesday_noon) / 0.1
        )


class TestSimClockRotation:
    """A --sim-clock run is asked for a window of N simulated days; the default
    10MB x 5 rotation silently deletes the oldest part of that window, and
    truncates each table by a different amount (high-volume feeds lose days
    while low-volume feeds keep everything), skewing cross-table correlation."""

    def test_sim_clock_mode_disables_rotation(self):
        from main import _rotation_limits

        max_bytes, _ = _rotation_limits(sim_clock=True)
        assert max_bytes == 0, "sim-clock output must not rotate away the requested window"

    def test_real_time_mode_keeps_bounded_rotation(self):
        from main import _rotation_limits

        max_bytes, backup_count = _rotation_limits(sim_clock=False)
        assert max_bytes > 0 and backup_count > 0

    def test_file_output_retains_everything_when_rotation_disabled(self, tmp_path):
        from kinetix.outputs.file import FileOutput
        from kinetix.schemas.network import DNSEvent

        out = FileOutput(output_dir=str(tmp_path), max_bytes=0)
        for i in range(2000):
            out.write(DNSEvent(Name=f"host{i}.example.com", hostname="WS-01"))

        assert list(tmp_path.glob("*.json.1")) == [], "rotation happened despite max_bytes=0"
        written = (tmp_path / "DnsEvents.json").read_text(encoding="utf-8").strip().splitlines()
        assert len(written) == 2000


class TestNoiseTemplateLoading:
    """The widened noise pool was resolved relative to the process working
    directory, so running main.py by absolute path from anywhere other than
    the repo root silently collapsed the pool from ~200 templates back to the
    15 inline ones. The fallback emits the same table names, so the loss is
    invisible in the output."""

    def test_noise_pool_loads_regardless_of_working_directory(self, tmp_path, monkeypatch):
        import main

        monkeypatch.chdir(tmp_path)
        templates = main._load_noise_scenario_templates(main._NOISE_SCENARIO_FILES)

        assert len(templates) > len(main._BENIGN_NOISE_TEMPLATES), (
            "noise scenario files did not resolve from outside the repo root"
        )

    def test_missing_noise_file_is_logged(self, caplog):
        import logging
        import main

        with caplog.at_level(logging.WARNING):
            main._load_noise_scenario_templates(["scenarios/does_not_exist.json"])

        assert "does_not_exist.json" in caplog.text


class TestSyslogFormat:
    """RFC 3164 carries no year ('%b %d %H:%M:%S'), so a backdated --sim-start
    was silently re-dated to the ingest year by the receiving collector, while
    the JSON and CEF feeds from the same run carried the correct year."""

    @pytest.fixture(autouse=True)
    def _reset_format(self):
        from kinetix.schemas import base
        yield
        base.set_syslog_format("rfc3164")

    def test_rfc3164_is_the_default_and_omits_the_year(self):
        from datetime import datetime, timezone
        from kinetix.schemas.base import format_syslog

        dt = datetime(2025, 1, 5, 14, 30, 0, tzinfo=timezone.utc)
        line = format_syslog(38, dt, "WS-01", "sshd", 4242, "hello")

        assert line.startswith("<38>Jan 05 14:30:00 WS-01 sshd[4242]: ")
        assert "2025" not in line

    def test_rfc5424_preserves_the_year(self):
        from datetime import datetime, timezone
        from kinetix.schemas.base import format_syslog, set_syslog_format

        set_syslog_format("rfc5424")
        dt = datetime(2025, 1, 5, 14, 30, 0, tzinfo=timezone.utc)
        line = format_syslog(38, dt, "WS-01", "sshd", 4242, "hello")

        assert line.startswith("<38>1 2025-01-05T14:30:00")
        assert "hello" in line

    def test_event_syslog_output_honours_the_selected_format(self):
        """The 30 to_syslog() overrides all funnel through format_syslog, so
        switching the format must reach real events, not just the helper."""
        from datetime import datetime, timezone
        from kinetix.schemas.linux import LinuxAuthEvent
        from kinetix.schemas.base import set_syslog_format

        e = LinuxAuthEvent(hostname="srv-01", user_name="alice",
                           ProcessId=4242, Message="Accepted password for alice",
                           timestamp=datetime(2025, 1, 5, 14, 30, tzinfo=timezone.utc))
        assert "2025" not in e.to_syslog()

        set_syslog_format("rfc5424")
        assert "2025-01-05T14:30:00" in e.to_syslog()

    def test_backdated_sim_start_under_rfc3164_warns(self, tmp_path):
        """--output-dir is not optional here: without it this invokes a real
        sim-clock generation into the repo's own logs/ directory, which on a
        lab box is the directory a wazuh-agent tails — every test run then
        injected ~12k events backdated to 2021 into the live SIEM."""
        from click.testing import CliRunner
        from main import main

        result = CliRunner().invoke(
            main, ["--sim-clock", "--sim-start", "2021-01-05", "--sim-days", "1",
                   "--duration", "5", "--output-dir", str(tmp_path)]
        )

        assert "rfc5424" in result.output.lower()


class TestOutputOrdering:
    """SimulatedClock.advance() hands out monotonic timestamps under a lock,
    but workers write in completion order, so a sim-clock run's files were
    ~11% out of order with backward jumps of several minutes."""

    def _write(self, path, timestamps):
        import orjson
        with open(path, "wb") as f:
            for ts in timestamps:
                f.write(orjson.dumps({"TimeGenerated": ts, "Type": "T"}) + b"\n")

    def test_sort_orders_a_shuffled_file_in_place(self, tmp_path):
        from main import _sort_jsonl_by_timestamp

        p = tmp_path / "DnsEvents.json"
        self._write(p, [
            "2026-09-18T10:00:05+00:00",
            "2026-09-18T10:00:01+00:00",
            "2026-09-18T10:00:09+00:00",
            "2026-09-18T10:00:03+00:00",
        ])

        _sort_jsonl_by_timestamp(str(p))

        import json
        got = [json.loads(l)["TimeGenerated"] for l in p.read_text().splitlines() if l.strip()]
        assert got == sorted(got)
        assert len(got) == 4

    def test_sort_preserves_every_line(self, tmp_path):
        import random
        from main import _sort_jsonl_by_timestamp

        p = tmp_path / "SigninLogs.json"
        stamps = [f"2026-09-18T10:{m:02d}:{s:02d}+00:00" for m in range(20) for s in range(30)]
        shuffled = stamps[:]
        random.shuffle(shuffled)
        self._write(p, shuffled)

        _sort_jsonl_by_timestamp(str(p))

        import json
        got = [json.loads(l)["TimeGenerated"] for l in p.read_text().splitlines() if l.strip()]
        assert got == sorted(stamps)

    def test_sort_leaves_unparseable_lines_in_place_without_crashing(self, tmp_path):
        from main import _sort_jsonl_by_timestamp

        p = tmp_path / "Broken.json"
        p.write_text('{"TimeGenerated": "2026-09-18T10:00:05+00:00"}\nnot json\n'
                     '{"TimeGenerated": "2026-09-18T10:00:01+00:00"}\n')

        _sort_jsonl_by_timestamp(str(p))

        lines = [l for l in p.read_text().splitlines() if l.strip()]
        assert len(lines) == 3, "sorting must not drop malformed lines"


class TestSimDaysValidation:
    def test_non_positive_sim_days_exits_with_a_message(self):
        from click.testing import CliRunner
        from main import main

        result = CliRunner().invoke(main, ["--sim-clock", "--sim-days", "0"])

        assert result.exit_code == 1
        assert not isinstance(result.exception, ValueError), (
            f"raw traceback escaped instead of a clean exit: {result.exception!r}"
        )
        assert "--sim-days" in result.output


class TestBaselineNoiseInterleave:
    """--baseline-ratio built a single noise stage holding the whole batch and
    appended that same dict after every attack stage, so `noise_count` events
    were emitted once per stage instead of once per cycle. With 23 stages a
    512-event batch became 11,776 events, overflowing the 10,000-slot engine
    queue inside a single cycle and starving the writer."""

    def _stages(self, n):
        return [{"name": f"stage-{i}", "delay": 0.1, "events": [f"attack-{i}"]}
                for i in range(n)]

    def test_noise_batch_is_emitted_once_per_cycle(self):
        import main

        stages = self._stages(23)
        noise = [f"noise-{j}" for j in range(512)]

        result = main._interleave_baseline_noise(stages, noise)
        emitted = sum(len(s["events"]) for s in result if s["name"] == "Baseline Noise")

        assert emitted == len(noise), (
            f"noise batch replayed per stage: {emitted} events emitted for a "
            f"{len(noise)}-event batch across {len(stages)} stages"
        )

    def test_every_noise_event_is_emitted_exactly_once(self):
        import main

        stages = self._stages(7)
        noise = [f"noise-{j}" for j in range(30)]

        result = main._interleave_baseline_noise(stages, noise)
        emitted = [e for s in result if s["name"] == "Baseline Noise" for e in s["events"]]

        assert sorted(emitted) == sorted(noise)

    def test_noise_is_spread_across_the_chain_not_bunched_at_one_point(self):
        import main

        stages = self._stages(6)
        noise = [f"noise-{j}" for j in range(60)]

        result = main._interleave_baseline_noise(stages, noise)
        noise_stages = [s for s in result if s["name"] == "Baseline Noise"]

        assert len(noise_stages) > 1, "noise collapsed into a single burst"
        assert max(len(s["events"]) for s in noise_stages) <= 15, (
            "noise unevenly bunched into one stage"
        )

    def test_attack_stages_are_preserved_in_order(self):
        import main

        stages = self._stages(5)
        result = main._interleave_baseline_noise(stages, ["n0", "n1", "n2"])
        attack = [s["name"] for s in result if s["name"] != "Baseline Noise"]

        assert attack == [s["name"] for s in stages]

    def test_more_stages_than_noise_events_emits_each_event_once(self):
        import main

        stages = self._stages(10)
        noise = ["n0", "n1", "n2"]

        result = main._interleave_baseline_noise(stages, noise)
        emitted = [e for s in result if s["name"] == "Baseline Noise" for e in s["events"]]

        assert sorted(emitted) == sorted(noise)
        assert all(s["events"] for s in result), "empty noise stage emitted"


class TestBusinessHoursTimezone:
    """calculate_delay() compared a UTC-stamped event against working_hours
    9-17, which are business-local hours. For an operator in UTC-8 a 14:50
    local workday run reads as 06:50 "after hours", so every event took the
    after_hours divisor (0.1) and the 0.2s base became 2.0s. With 2 workers
    that caps drain at ~1 event/sec and any --baseline-ratio run fills the
    10,000-slot queue and starts dropping."""

    def _profile(self, **kwargs):
        from kinetix.schemas.temporal import TimingProfile
        return TimingProfile(avg_delay_seconds=1.0, jitter_percent=0.0, **kwargs)

    def test_offset_defaults_to_utc_so_existing_behaviour_is_unchanged(self):
        from kinetix.schemas.temporal import TimingProfile
        assert TimingProfile().business_utc_offset_hours == 0.0

    def test_local_working_hours_are_not_throttled(self):
        from datetime import datetime, timezone
        from kinetix.core.temporal import TemporalEngine

        # 14:50 in UTC-8 == 22:50 UTC. Business-local this is a workday
        # afternoon, so it must not take the after-hours divisor.
        te = TemporalEngine(profile=self._profile(business_utc_offset_hours=-8))
        local_afternoon = datetime(2026, 9, 21, 22, 50, tzinfo=timezone.utc)

        assert te.calculate_delay(local_afternoon) == pytest.approx(1.0)

    def test_local_night_is_still_throttled(self):
        from datetime import datetime, timezone
        from kinetix.core.temporal import TemporalEngine

        # 03:00 in UTC-8 == 11:00 UTC: daytime in UTC, night business-local.
        te = TemporalEngine(profile=self._profile(business_utc_offset_hours=-8))
        local_night = datetime(2026, 9, 21, 11, 0, tzinfo=timezone.utc)

        assert te.calculate_delay(local_night) == pytest.approx(1.0 / 0.1)

    def test_offset_shifts_the_weekend_boundary_too(self):
        from datetime import datetime, timezone
        from kinetix.core.temporal import TemporalEngine

        # Sat 2026-09-19 02:00 UTC is still Friday 18:00 business-local.
        te = TemporalEngine(profile=self._profile(
            business_utc_offset_hours=-8, weekend_shaping=True))
        still_friday = datetime(2026, 9, 19, 2, 0, tzinfo=timezone.utc)

        assert te.calculate_delay(still_friday) == pytest.approx(
            te.calculate_delay(datetime(2026, 9, 18, 2, 0, tzinfo=timezone.utc))
        ), "weekend divisor applied to a business-local Friday"

    def test_realtime_run_uses_the_host_local_offset(self):
        """Without this the documented --baseline-ratio mode cannot drain."""
        import main
        profile = main._build_timing_profile(delay=0.2, sim_clock=False)

        from datetime import datetime
        expected = datetime.now().astimezone().utcoffset().total_seconds() / 3600
        assert profile.business_utc_offset_hours == pytest.approx(expected)

    def test_sim_clock_stays_utc_native(self):
        import main
        profile = main._build_timing_profile(delay=0.2, sim_clock=True)
        assert profile.business_utc_offset_hours == 0.0


class TestVendorFeeds:
    """Vendor-native wire formats for sources Wazuh 5.0 decodes natively.

    Sentinel-shaped JSON is claimed by no enabled 5.0 integration, and the
    Windows Filtering Platform codes a firewall would otherwise map to are on
    decoder/windows-event/0's discard list. Emitting what the real appliance
    emits is the only path that both indexes and stays honest about
    provenance.
    """

    def _fw(self, **kw):
        from kinetix.schemas.network import FirewallEvent
        base = dict(DeviceAction="allowed", Protocol="TCP", SourcePort=49152,
                    DestinationPort=443, hostname="FGT-EDGE-01")
        base.update(kw)
        return FirewallEvent(**base)

    def test_base_event_emits_no_vendor_feed(self):
        """Self-gating like to_auditd(): a source with no vendor equivalent
        contributes nothing, so there is no source list to keep in sync."""
        from kinetix.schemas.endpoint import ProcessEvent
        ev = ProcessEvent(FileName="a.exe", ProcessId=1, ProcessCommandLine="a")
        assert ev.to_vendor_feeds() == []

    def test_firewall_event_writes_a_fortinet_feed_line(self):
        feeds = dict(self._fw().to_vendor_feeds())
        assert "Kinetix_Fortinet.log" in feeds

    def test_every_fortinet_line_satisfies_the_wazuh_decoder_gate(self):
        """decoder/fortinet-start/0 gates on:
             contains($event.original, " type=") AND
             contains($event.original, " time=") AND
             (contains($event.original, " subtype=") OR ...)
        and parses '$PRIORITY<_tmp_log>', so the line must also carry a
        syslog priority prefix. A line failing any of these is discarded by
        the manager with no error anywhere."""
        import re
        for action in ("allowed", "blocked", "dropped"):
            for direction in ("Inbound", "Outbound"):
                line = dict(self._fw(DeviceAction=action, NetworkDirection=direction)
                            .to_vendor_feeds())["Kinetix_Fortinet.log"]
                assert re.match(r"^<\d{1,3}>", line), f"no syslog priority: {line[:40]}"
                assert " type=" in line
                assert " time=" in line
                assert " subtype=" in line
                assert "\n" not in line

    def test_fortinet_line_declares_the_traffic_type(self):
        """_fortinet.type selects the child decoder: string_equal("traffic")
        routes to decoder/fortinet-traffic/0, which is the one that extracts
        the session fields."""
        line = dict(self._fw().to_vendor_feeds())["Kinetix_Fortinet.log"]
        assert 'type="traffic"' in line
        assert 'subtype="forward"' in line

    def test_fortinet_line_carries_the_session_fields(self):
        ev = self._fw(DeviceAction="blocked", Protocol="TCP", SourcePort=51000,
                      DestinationPort=8443, IPAddress="10.20.30.40",
                      DestinationIP="203.0.113.9", SentBytes=1200, ReceivedBytes=350)
        line = dict(ev.to_vendor_feeds())["Kinetix_Fortinet.log"]
        assert "srcip=10.20.30.40" in line
        assert "dstip=203.0.113.9" in line
        assert "srcport=51000" in line
        assert "dstport=8443" in line
        assert "proto=6" in line          # TCP as an IANA protocol number
        assert 'action="deny"' in line    # FortiOS vocabulary, not Kinetix's
        assert "sentbyte=1200" in line
        assert "rcvdbyte=350" in line

    def test_fortinet_allowed_action_uses_fortios_accept(self):
        line = dict(self._fw(DeviceAction="allowed").to_vendor_feeds())["Kinetix_Fortinet.log"]
        assert 'action="accept"' in line

    def test_firewall_vendor_defaults_to_fortigate(self):
        feeds = dict(self._fw().to_vendor_feeds())
        assert list(feeds) == ["Kinetix_Fortinet.log"]

    def test_firewall_vendor_asa_emits_only_the_asa_feed(self):
        """One session comes off one appliance, so a device flavour selects
        the feed rather than every event appearing in both."""
        feeds = dict(self._fw(vendor="asa").to_vendor_feeds())
        assert list(feeds) == ["Kinetix_CiscoASA.log"]

    def test_asa_line_satisfies_the_wazuh_decoder_gate(self):
        """The ASA path runs decoder/syslog/0 -> decoder/cisco-asa/0, and
        syslog/0 parses the tag as '<_TAG/alphanumeric/->:'. '%ASA-4-106023'
        cannot BE the tag — the leading % is not alphanumeric, the syslog
        parse fails, and cisco-asa/0 never receives a $message to work on.
        So the line needs a real tag ("asa:") and the %ASA-level-id has to sit
        at the start of the message after it.

        Ingest-verified 2026-09-22: this shape indexed, while the same line
        without the tag produced zero documents despite the agent reading it
        with drops=0."""
        import re
        for action in ("allowed", "blocked"):
            line = dict(self._fw(DeviceAction=action, vendor="asa")
                        .to_vendor_feeds())["Kinetix_CiscoASA.log"]
            assert re.match(r"^<\d{1,3}>[A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} \S+ [a-z0-9-]+: %ASA-\d-\d{6}: ", line), line[:100]
            assert "%FTD" not in line, "the ASA decoder excludes anything carrying %FTD"
            assert "\n" not in line

    def test_asa_allowed_session_is_a_built_connection(self):
        ev = self._fw(DeviceAction="allowed", vendor="asa", IPAddress="10.20.30.40",
                      DestinationIP="203.0.113.9", SourcePort=51000, DestinationPort=8443)
        line = dict(ev.to_vendor_feeds())["Kinetix_CiscoASA.log"]
        assert "%ASA-6-302013" in line
        assert "Built outbound TCP connection" in line
        assert "10.20.30.40/51000" in line
        assert "203.0.113.9/8443" in line

    def test_asa_blocked_session_is_an_acl_deny(self):
        ev = self._fw(DeviceAction="blocked", vendor="asa", IPAddress="10.20.30.40",
                      DestinationIP="203.0.113.9", SourcePort=51000, DestinationPort=8443)
        line = dict(ev.to_vendor_feeds())["Kinetix_CiscoASA.log"]
        assert "%ASA-4-106023" in line
        assert "Deny tcp src" in line
        assert "by access-group" in line

    def test_dns_event_is_a_dns_server_analytical_record(self):
        """decoder/microsoft-dnsserver-analytical/0 hangs off windows-event
        and selects on event.dataset == 'microsoft-windows-dnsserver/analytical',
        which windows-event sets from downcase(Channel). So the DNS feed rides
        the existing EVTX file — no new feed, no manager-side collector — as
        long as the Channel is right. Server-side analytical logging is also
        what a SOC actually collects; DNS Client 3008 is endpoint-local."""
        from kinetix.schemas.network import DNSEvent
        ev = DNSEvent(Name="evil.example.com", QueryType="A", hostname="DC-DNS-01",
                      IPAddresses="203.0.113.10")
        evt = ev.to_evt()
        assert "Channel>Microsoft-Windows-DNSServer/Analytical<" in evt
        assert "Provider Name='Microsoft-Windows-DNSServer'" in evt
        assert "EventID>256<" in evt

    def test_dns_event_carries_the_fields_the_decoder_reads(self):
        """The decoder maps dns.question.name from EventData.QNAME, dns.id
        from XID, destination.ip from Destination, and resolves
        dns.question.type by kvdb lookup on the numeric QTYPE."""
        from kinetix.schemas.network import DNSEvent
        evt = DNSEvent(Name="evil.example.com", QueryType="AAAA", hostname="DC-DNS-01",
                       IPAddresses="203.0.113.10").to_evt()
        assert "Name='QNAME'>evil.example.com<" in evt
        assert "Name='QTYPE'>28<" in evt      # AAAA as its numeric RR type
        assert "Name='XID'>" in evt
        assert "Name='Destination'>" in evt

    def test_dns_query_type_falls_back_for_unknown_records(self):
        from kinetix.schemas.network import DNSEvent
        evt = DNSEvent(Name="x.example.com", QueryType="WEIRD").to_evt()
        assert "Name='QTYPE'>1<" in evt

    def test_dns_events_reach_the_evt_feed(self, tmp_path):
        """DNS was excluded from EVT as a non-Windows appliance source. A
        Microsoft DNS Server is a genuine Windows Event Log producer, so the
        exclusion was what kept this telemetry out of Wazuh."""
        from kinetix.outputs.file import FileOutput
        from kinetix.schemas.network import DNSEvent
        out = FileOutput(output_dir=str(tmp_path), max_bytes=0)
        out.write(DNSEvent(Name="evil.example.com", hostname="DC-DNS-01"))
        evtx = (tmp_path / "Kinetix_EVTX.log").read_text(encoding="utf-8")
        assert "Microsoft-Windows-DNSServer/Analytical" in evtx

    def test_authentication_event_writes_an_okta_system_log_record(self):
        """decoder/okta-system/0 gates on the JSON carrying eventType, uuid
        and published. Okta is the identity source Kinetix's SSO and OAuth
        scenarios are actually modelling, and the Sentinel-shaped SigninLogs
        JSON is claimed by no enabled 5.0 integration."""
        import json as _json
        from kinetix.schemas.cloud_auth import AuthenticationEvent
        ev = AuthenticationEvent(UserPrincipalName="alice@corp.com", ResultType="0",
                                 IPAddress="10.20.30.40")
        feeds = dict(ev.to_vendor_feeds())
        assert "Kinetix_Okta.json" in feeds
        rec = _json.loads(feeds["Kinetix_Okta.json"])
        assert rec["eventType"]
        assert rec["uuid"]
        assert rec["published"]
        assert rec["outcome"]["result"] == "SUCCESS"
        assert rec["actor"]["alternateId"] == "alice@corp.com"

    def test_failed_authentication_is_an_okta_failure_outcome(self):
        import json as _json
        from kinetix.schemas.cloud_auth import AuthenticationEvent
        ev = AuthenticationEvent(UserPrincipalName="root@corp.com", ResultType="50126")
        rec = _json.loads(dict(ev.to_vendor_feeds())["Kinetix_Okta.json"])
        assert rec["outcome"]["result"] == "FAILURE"
        assert rec["eventType"] == "user.session.start"

    def test_okta_failure_reason_is_not_the_default_success_string(self):
        """result_description defaults to "Success" on the Sentinel schema,
        so a failed sign-in that does not override it produced
        outcome.result=FAILURE with outcome.reason=Success — a contradiction
        that lands in event.reason on the Wazuh side."""
        import json as _json
        from kinetix.schemas.cloud_auth import AuthenticationEvent
        rec = _json.loads(dict(AuthenticationEvent(
            UserPrincipalName="root@corp.com", ResultType="50126").to_vendor_feeds())["Kinetix_Okta.json"])
        assert rec["outcome"]["result"] == "FAILURE"
        assert rec["outcome"]["reason"] != "Success"

    def test_okta_failure_keeps_an_explicit_reason(self):
        import json as _json
        from kinetix.schemas.cloud_auth import AuthenticationEvent
        rec = _json.loads(dict(AuthenticationEvent(
            UserPrincipalName="root@corp.com", ResultType="50126",
            ResultDescription="Invalid username or password").to_vendor_feeds())["Kinetix_Okta.json"])
        assert rec["outcome"]["reason"] == "Invalid username or password"

    def test_okta_record_is_one_line_of_json(self):
        """The agent reads this feed with log_format json, one record per
        line — an embedded newline would split a record in half."""
        from kinetix.schemas.cloud_auth import AuthenticationEvent
        line = dict(AuthenticationEvent(UserPrincipalName="a@b.com").to_vendor_feeds())["Kinetix_Okta.json"]
        assert "\n" not in line

    def test_file_output_writes_the_fortinet_feed(self, tmp_path):
        """A dedicated feed file per vendor, like Kinetix_Auditd.log: the
        agent tails a file whose every line one decoder claims, instead of a
        mixed stream the decoder has to sift."""
        from kinetix.outputs.file import FileOutput
        out = FileOutput(output_dir=str(tmp_path), max_bytes=0)
        out.write(self._fw(DeviceAction="blocked"))

        feed = tmp_path / "Kinetix_Fortinet.log"
        assert feed.exists(), "vendor feed file was not created"
        lines = feed.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        assert 'type="traffic"' in lines[0]

    def test_file_output_skips_the_vendor_feed_for_unrelated_events(self, tmp_path):
        from kinetix.outputs.file import FileOutput
        from kinetix.schemas.endpoint import ProcessEvent
        out = FileOutput(output_dir=str(tmp_path), max_bytes=0)
        out.write(ProcessEvent(FileName="a.exe", ProcessId=1, ProcessCommandLine="a"))

        assert not (tmp_path / "Kinetix_Fortinet.log").exists()

    def test_fortinet_timestamp_comes_from_the_event(self):
        """--sim-clock backdating has to survive into the vendor feed, the
        same reason EVTX needs TimeCreated."""
        from datetime import datetime, timezone
        ev = self._fw(TimeGenerated=datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc))
        line = dict(ev.to_vendor_feeds())["Kinetix_Fortinet.log"]
        assert "date=2026-03-04" in line
        assert "time=05:06:07" in line


class TestAuditdOutput:
    """auditd wire-format output — Wazuh 5.0's auditd decoder gates on
    `starts_with($event.original, "node=") OR starts_with($event.original, "type=")`,
    so every emitted line must satisfy that or the manager silently discards it."""

    WAZUH_GATE = ("type=", "node=")

    def _all_linux_events(self):
        from kinetix.schemas.linux import (
            LinuxAuthEvent, LinuxSudoEvent, LinuxAuditdEvent,
            LinuxCronEvent, LinuxProcessEvent, LinuxKernelEvent,
        )
        return [
            LinuxAuthEvent(pid=1234, proc="sshd", log_message="Accepted password for alice from 10.0.0.1 port 22 ssh2"),
            LinuxAuthEvent(pid=1235, proc="sshd", log_message="Failed password for root from 10.0.0.1 port 22 ssh2"),
            LinuxSudoEvent(pid=1236, user="alice", command="cat /etc/shadow", hostname="web-01"),
            LinuxAuditdEvent(pid=1237, hostname="db-01", audit_type="SYSCALL",
                             audit_msg="arch=c000003e syscall=59 success=yes", auid=1000, ses=3),
            LinuxCronEvent(pid=1238, user="root", command="run-parts /etc/cron.hourly"),
            LinuxProcessEvent(pid=1239, ppid=1200, exe="/usr/bin/nmap", args="nmap -sS 10.0.0.0/24",
                              user="alice", uid=1000, gid=1000),
            LinuxKernelEvent(pid=0, log_message="CPU threshold exceeded"),
        ]

    def test_base_event_has_no_auditd_representation(self):
        from kinetix.schemas.endpoint import ProcessEvent
        ev = ProcessEvent(FileName="cmd.exe", FolderPath="C:\\Windows\\System32",
                          ProcessId=1234, ProcessCommandLine="cmd.exe /c whoami")
        assert ev.to_auditd() == []

    def test_auditd_event_renders_syscall_record(self):
        from kinetix.schemas.linux import LinuxAuditdEvent
        ev = LinuxAuditdEvent(pid=1237, hostname="db-01", audit_type="SYSCALL",
                              audit_msg="arch=c000003e syscall=59 success=yes", auid=1000, ses=3)
        lines = ev.to_auditd()
        assert len(lines) == 1
        assert lines[0].startswith("type=SYSCALL msg=audit(")
        assert "auid=1000" in lines[0]
        assert "ses=3" in lines[0]

    def test_auth_success_renders_user_login(self):
        from kinetix.schemas.linux import LinuxAuthEvent
        ev = LinuxAuthEvent(pid=1234, proc="sshd",
                            log_message="Accepted password for alice from 10.0.0.1 port 22 ssh2")
        line = ev.to_auditd()[0]
        assert line.startswith("type=USER_LOGIN ")
        assert "res=success" in line

    def test_auth_failure_renders_user_auth_with_failed_result(self):
        from kinetix.schemas.linux import LinuxAuthEvent
        ev = LinuxAuthEvent(pid=1235, proc="sshd",
                            log_message="Failed password for root from 10.0.0.1 port 22 ssh2")
        line = ev.to_auditd()[0]
        assert line.startswith("type=USER_AUTH ")
        assert "res=failed" in line

    def test_sudo_renders_user_cmd_with_hex_encoded_command(self):
        from kinetix.schemas.linux import LinuxSudoEvent
        ev = LinuxSudoEvent(pid=1236, user="alice", command="cat /etc/shadow", hostname="web-01")
        line = ev.to_auditd()[0]
        assert line.startswith("type=USER_CMD ")
        # real auditd hex-encodes commands containing spaces
        assert "cmd=" + "cat /etc/shadow".encode().hex() in line
        assert "cat /etc/shadow" not in line

    def test_process_renders_syscall_and_execve_sharing_one_serial(self):
        from kinetix.schemas.linux import LinuxProcessEvent
        import re
        ev = LinuxProcessEvent(pid=1239, ppid=1200, exe="/usr/bin/nmap",
                               args="nmap -sS 10.0.0.0/24", user="alice", uid=1000, gid=1000)
        lines = ev.to_auditd()
        assert len(lines) == 2
        assert lines[0].startswith("type=SYSCALL ")
        assert lines[1].startswith("type=EXECVE ")
        serials = [re.search(r"msg=audit\([0-9.]+:(\d+)\)", l).group(1) for l in lines]
        assert serials[0] == serials[1], "SYSCALL and EXECVE of one event must share a serial"

    def test_execve_splits_args_into_numbered_fields(self):
        from kinetix.schemas.linux import LinuxProcessEvent
        ev = LinuxProcessEvent(pid=1239, ppid=1200, exe="/usr/bin/nmap",
                               args="nmap -sS 10.0.0.0/24", user="alice", uid=1000, gid=1000)
        execve = ev.to_auditd()[1]
        assert "argc=3" in execve
        assert 'a0="nmap"' in execve
        assert 'a1="-sS"' in execve
        assert 'a2="10.0.0.0/24"' in execve

    def test_cron_renders_cred_acq(self):
        from kinetix.schemas.linux import LinuxCronEvent
        ev = LinuxCronEvent(pid=1238, user="root", command="run-parts /etc/cron.hourly")
        line = ev.to_auditd()[0]
        assert line.startswith("type=CRED_ACQ ")

    def test_serials_are_unique_across_distinct_events(self):
        from kinetix.schemas.linux import LinuxCronEvent
        import re
        a = LinuxCronEvent(pid=1, user="root", command="a").to_auditd()[0]
        b = LinuxCronEvent(pid=2, user="root", command="b").to_auditd()[0]
        sa = re.search(r"msg=audit\([0-9.]+:(\d+)\)", a).group(1)
        sb = re.search(r"msg=audit\([0-9.]+:(\d+)\)", b).group(1)
        assert sa != sb

    def test_timestamp_derives_from_event_time_not_wall_clock(self):
        """--sim-clock backdates events; auditd lines must carry that time, not now()."""
        from kinetix.schemas.linux import LinuxCronEvent
        from datetime import datetime, timezone
        import re
        backdated = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        ev = LinuxCronEvent(pid=1238, user="root", command="x", TimeGenerated=backdated)
        line = ev.to_auditd()[0]
        epoch = float(re.search(r"msg=audit\(([0-9.]+):", line).group(1))
        assert abs(epoch - backdated.timestamp()) < 1.0

    def test_every_auditd_line_satisfies_wazuh_decoder_gate(self):
        """Regression: a line failing this gate is silently dropped by the manager."""
        for ev in self._all_linux_events():
            for line in ev.to_auditd():
                assert line.startswith(self.WAZUH_GATE), \
                    f"{type(ev).__name__} emitted a line the Wazuh auditd decoder would discard: {line[:80]!r}"

    def test_auditd_lines_are_single_line(self):
        for ev in self._all_linux_events():
            for line in ev.to_auditd():
                assert "\n" not in line and "\r" not in line


class TestAuditdFeed:
    """The unified Kinetix_Auditd.log feed written by FileOutput."""

    def _write(self, tmp_path, events):
        from kinetix.outputs.file import FileOutput
        fo = FileOutput(str(tmp_path))
        for ev in events:
            fo.write(ev)
        fo.flush()
        fo.close()
        return tmp_path / "Kinetix_Auditd.log"

    def test_linux_event_lands_in_auditd_feed(self, tmp_path):
        from kinetix.schemas.linux import LinuxSudoEvent
        ev = LinuxSudoEvent(pid=4242, user="alice", command="cat /etc/shadow", hostname="web-01")
        feed = self._write(tmp_path, [ev])
        lines = [l for l in feed.read_text().splitlines() if l.strip()]
        assert len(lines) == 1
        assert lines[0].startswith("type=USER_CMD ")

    def test_process_event_writes_both_records(self, tmp_path):
        from kinetix.schemas.linux import LinuxProcessEvent
        ev = LinuxProcessEvent(pid=99, ppid=1, exe="/usr/bin/nmap",
                               args="nmap -sS 10.0.0.0/24", user="alice")
        feed = self._write(tmp_path, [ev])
        lines = [l for l in feed.read_text().splitlines() if l.strip()]
        assert len(lines) == 2
        assert lines[0].startswith("type=SYSCALL ")
        assert lines[1].startswith("type=EXECVE ")

    def test_windows_event_produces_no_auditd_lines(self, tmp_path):
        from kinetix.schemas.endpoint import ProcessEvent
        ev = ProcessEvent(FileName="cmd.exe", FolderPath="C:\\Windows\\System32",
                          ProcessId=1234, ProcessCommandLine="cmd.exe /c whoami")
        feed = self._write(tmp_path, [ev])
        # the feed file is always created; it must simply have no records in it
        assert feed.exists(), "auditd feed should be created even when empty"
        assert feed.read_text().strip() == ""

    def test_feed_lines_all_satisfy_wazuh_gate(self, tmp_path):
        from kinetix.schemas.linux import (
            LinuxAuthEvent, LinuxSudoEvent, LinuxAuditdEvent, LinuxCronEvent, LinuxProcessEvent,
        )
        from kinetix.schemas.endpoint import ProcessEvent
        events = [
            LinuxAuthEvent(pid=1, proc="sshd", log_message="Failed password for root from 10.0.0.1 port 22 ssh2"),
            LinuxSudoEvent(pid=2, user="bob", command="id"),
            LinuxAuditdEvent(pid=3, audit_type="SYSCALL", audit_msg="arch=c000003e syscall=2"),
            LinuxCronEvent(pid=4, user="root", command="backup.sh"),
            LinuxProcessEvent(pid=5, exe="/bin/sh", args="sh -c whoami", user="root"),
            ProcessEvent(FileName="cmd.exe", ProcessId=6, ProcessCommandLine="cmd /c dir"),
        ]
        feed = self._write(tmp_path, events)
        lines = [l for l in feed.read_text().splitlines() if l.strip()]
        assert lines, "expected auditd lines from the Linux events"
        for line in lines:
            assert line.startswith(("type=", "node=")), \
                f"Wazuh auditd decoder would discard: {line[:80]!r}"


class TestDurationDeadline:
    """`--duration` was only checked after AttackChain.run() returned, so a
    single cycle could overrun it without limit. A 180s run was observed
    still generating 19 hours later: --baseline-ratio 0.95 across 6 scenarios
    builds a cycle of tens of thousands of events, engine.emit() blocks up to
    1.0s per event once the 10,000-slot queue fills, and nothing inside the
    chain looked at the clock or the stop event. The deadline has to be
    enforced *during* a cycle, at every point the chain can block.
    """

    class FakeEngine:
        """Records emits. Optionally sets a stop event on the Nth emit, which
        is how a real Ctrl+C arrives mid-stage."""

        def __init__(self, stop_event=None, stop_after=None):
            self.emitted = []
            self.stop_event = stop_event
            self.stop_after = stop_after

        def emit(self, event):
            self.emitted.append(event)
            if self.stop_after is not None and len(self.emitted) >= self.stop_after:
                self.stop_event.set()

    def _chain(self, stage_count=3, events_per_stage=4, delay=1.0):
        from kinetix.core.scenario import AttackChain

        class Ev:
            def __init__(self, tag):
                self.tag = tag
                self.scenario_id = None

        stages = [
            {
                "name": f"stage-{i}",
                "delay": delay,
                "events": [Ev(f"s{i}e{j}") for j in range(events_per_stage)],
            }
            for i in range(stage_count)
        ]
        return AttackChain(scenario_id="test", name="deadline", stages=stages)

    def test_no_stage_runs_when_deadline_already_passed(self):
        import time

        chain = self._chain()
        engine = self.FakeEngine()

        chain.run(engine, deadline=time.monotonic() - 1)

        assert engine.emitted == []

    def test_event_loop_stops_mid_stage_at_deadline(self, monkeypatch):
        import kinetix.core.scenario as scenario_mod

        # A synthetic clock that advances one second per reading makes the
        # cutoff deterministic: with a deadline 3 ticks out, the per-event
        # check must stop the stage partway instead of emitting all 50.
        ticks = iter(range(0, 1000))
        monkeypatch.setattr(scenario_mod.time, "monotonic", lambda: float(next(ticks)))

        chain = self._chain(stage_count=1, events_per_stage=50, delay=0)
        engine = self.FakeEngine()

        chain.run(engine, deadline=3.0)

        assert 0 < len(engine.emitted) < 50, f"emitted {len(engine.emitted)} of 50"

    def test_inter_stage_sleep_aborts_at_deadline(self):
        import time

        # Two 30s inter-stage delays: honouring them would take a minute.
        chain = self._chain(stage_count=3, events_per_stage=1, delay=30.0)
        engine = self.FakeEngine()

        started = time.monotonic()
        chain.run(engine, deadline=started + 0.3)
        wall = time.monotonic() - started

        assert wall < 5.0, f"chain slept {wall:.1f}s past its deadline"

    def test_event_loop_honours_stop_event_mid_stage(self):
        import threading

        stop = threading.Event()
        chain = self._chain(stage_count=1, events_per_stage=100, delay=0)
        engine = self.FakeEngine(stop_event=stop, stop_after=5)

        chain.run(engine, stop_event=stop)

        assert len(engine.emitted) == 5, f"kept emitting after stop: {len(engine.emitted)}"

    def test_chain_without_deadline_runs_every_stage(self):
        chain = self._chain(stage_count=3, events_per_stage=4, delay=0)
        engine = self.FakeEngine()

        chain.run(engine)

        assert len(engine.emitted) == 12

    def test_run_reports_whether_the_deadline_cut_it_short(self):
        import time

        chain = self._chain(stage_count=3, events_per_stage=2, delay=0)
        engine = self.FakeEngine()

        assert chain.run(engine, deadline=time.monotonic() - 1) is True
        assert chain.run(engine) is False

    def test_timed_run_exits_within_its_duration(self, tmp_path):
        """End-to-end guard on the wiring, not just AttackChain.

        This is the exact invocation that was observed still generating 19
        hours after a --duration 180 request. The bound is measured, not
        guessed: with the deadline enforced this exits in 5.3-5.4s over three
        runs; with the pre-fix post-cycle-only check it takes 31.5-31.6s,
        because one full cycle has to finish emitting and draining before the
        duration is ever consulted. 15s sits between the two with margin on
        both sides. A looser bound passes against the bug and guards nothing.
        """
        import subprocess
        import sys
        import time

        scenarios = [
            "scenarios/apt_lockbit_style.json",
            "scenarios/apt_volt_typhoon_style.json",
            "scenarios/linux_ssh_bruteforce.json",
            "scenarios/oauth_device_code_phishing.json",
            "scenarios/shadow_ai_data_exfiltration.json",
            "scenarios/adcs_certificate_abuse.json",
        ]
        cmd = [sys.executable, "main.py", "--baseline-ratio", "0.95",
               "--duration", "5", "--output-dir", str(tmp_path)]
        for s in scenarios:
            cmd += ["--scenario", s]

        started = time.monotonic()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        except subprocess.TimeoutExpired:
            pytest.fail("--duration 5 run did not exit within 45s")
        wall = time.monotonic() - started

        assert proc.returncode == 0, proc.stderr[-2000:]
        assert wall < 15, f"--duration 5 run took {wall:.0f}s"


class TestFollowUpBackpressure:
    """LogWorker enqueued Markov follow-ups with a bare, unbounded
    input_queue.put(). The workers are the queue's only consumers, so a full
    queue with every worker parked in put() can never drain: nothing
    consumes, stop_event is never observed, and the run wedges permanently.
    Follow-ups are derived noise, so shedding one under backpressure is
    strictly better than deadlocking.
    """

    class AlwaysFollowUp:
        """Temporal engine stub that always yields a follow-up, removing the
        Markov coin flip from these tests."""

        def __init__(self, factory):
            self.factory = factory

        def calculate_delay(self, _when):
            return 0.0

        def get_next_event_type(self, _event_type):
            return "DeviceProcessEvents"

        def create_follow_up(self, _parent, _next_type):
            return self.factory()

    def _event(self):
        from kinetix.schemas.endpoint import ProcessEvent
        return ProcessEvent(
            FileName="cmd.exe", FolderPath="C:\\Windows\\System32",
            ProcessId=1234, ProcessCommandLine="cmd.exe /c whoami",
        )

    def _worker(self, input_queue, stop_event=None):
        import threading
        from kinetix.core.worker import LogWorker
        return LogWorker(
            worker_id=0,
            input_queue=input_queue,
            output_providers=[],
            stop_event=stop_event or threading.Event(),
            temporal_engine=self.AlwaysFollowUp(self._event),
        )

    def test_follow_up_is_queued_when_there_is_room(self):
        import queue

        q = queue.Queue(maxsize=4)
        worker = self._worker(q)
        follow_up = self._event()

        assert worker._enqueue_follow_up(follow_up) is True
        assert q.get_nowait() is follow_up

    def test_full_queue_sheds_the_follow_up_instead_of_blocking(self):
        import queue
        import time

        # Nothing will ever drain this queue — the pre-fix unbounded put()
        # would sit here forever.
        q = queue.Queue(maxsize=1)
        q.put_nowait(self._event())
        worker = self._worker(q)

        started = time.monotonic()
        result = worker._enqueue_follow_up(self._event())
        waited = time.monotonic() - started

        assert result is False
        assert waited < 5.0, f"blocked {waited:.1f}s on a full queue"
        assert q.qsize() == 1

    def test_shed_follow_ups_are_counted(self):
        import queue

        q = queue.Queue(maxsize=1)
        q.put_nowait(self._event())
        worker = self._worker(q)

        assert worker.shed_follow_ups == 0
        worker._enqueue_follow_up(self._event())
        assert worker.shed_follow_ups == 1

    def test_stop_event_aborts_the_put_without_waiting_out_the_timeout(self):
        import queue
        import threading
        import time

        q = queue.Queue(maxsize=1)
        q.put_nowait(self._event())
        stop = threading.Event()
        stop.set()
        worker = self._worker(q, stop_event=stop)

        started = time.monotonic()
        assert worker._enqueue_follow_up(self._event()) is False
        assert time.monotonic() - started < 0.5

    def test_worker_pool_terminates_with_a_saturated_queue(self):
        """Pool-level guard reproducing the actual deadlock shape.

        A producer thread holds the queue full, standing in for AttackChain
        emitting faster than the pool drains — the normal state under
        --baseline-ratio. Every worker then blocks handing off its follow-up,
        and because the workers are the only consumers, the pre-fix unbounded
        put() leaves them waiting on each other with no one left to drain.
        Setting stop_event must still bring the pool down.
        """
        import queue
        import threading

        q = queue.Queue(maxsize=4)
        stop = threading.Event()
        producing = threading.Event()
        producing.set()

        def producer():
            while producing.is_set():
                try:
                    q.put(self._event(), timeout=0.05)
                except queue.Full:
                    continue

        filler = threading.Thread(target=producer, daemon=True)
        filler.start()

        workers = []
        for i in range(2):
            w = self._worker(q, stop_event=stop)
            w.worker_id = i
            w.daemon = True
            workers.append(w)
        for w in workers:
            w.start()

        # Let the producer saturate the queue and park the workers in put().
        threading.Event().wait(2.0)
        producing.clear()
        stop.set()

        for w in workers:
            w.join(timeout=20)
            assert not w.is_alive(), f"worker {w.worker_id} never exited"


class TestFirewallVendorTopology:
    """Which appliance a flow crosses follows the topology, not a coin flip.

    Every FirewallEvent defaulted to `fortigate`, and no scenario sets a
    vendor, so Kinetix_CiscoASA.log was never written by a real run — the
    enabled cisco-asa integration indexed nothing. The bulk of firewall
    telemetry comes from TemporalEngine.create_follow_up(), not from the six
    scenario events, so the split has to be decided there: egress to a public
    address crosses the perimeter ASA, east-west traffic stays on a FortiGate.
    """

    def _parent(self, dest_ip, source_ip="10.20.30.40"):
        from kinetix.schemas.endpoint import ProcessEvent
        return ProcessEvent(FileName="a.exe", ProcessId=1, ProcessCommandLine="a",
                            DestinationIP=dest_ip, source_ip=source_ip)

    def _follow_up(self, dest_ip, source_ip="10.20.30.40"):
        from kinetix.core.temporal import TemporalEngine
        return TemporalEngine().create_follow_up(
            self._parent(dest_ip, source_ip), "CommonSecurityLog")

    def test_egress_to_a_public_address_crosses_the_perimeter_asa(self):
        feeds = dict(self._follow_up("203.0.113.9").to_vendor_feeds())
        assert list(feeds) == ["Kinetix_CiscoASA.log"]

    def test_east_west_traffic_stays_on_a_fortigate(self):
        feeds = dict(self._follow_up("10.0.0.5").to_vendor_feeds())
        assert list(feeds) == ["Kinetix_Fortinet.log"]

    def test_rfc1918_172_16_range_is_treated_as_internal(self):
        feeds = dict(self._follow_up("172.16.4.9").to_vendor_feeds())
        assert list(feeds) == ["Kinetix_Fortinet.log"]

    def test_a_follow_up_with_no_destination_stays_internal(self):
        feeds = dict(self._follow_up(None).to_vendor_feeds())
        assert list(feeds) == ["Kinetix_Fortinet.log"]

    def test_inbound_scanning_from_the_internet_also_crosses_the_asa(self):
        """network_recon is 1.2.3.4 -> 10.0.0.5: the destination is internal,
        but the flow still entered through the perimeter."""
        feeds = dict(self._follow_up("10.0.0.5", source_ip="1.2.3.4").to_vendor_feeds())
        assert list(feeds) == ["Kinetix_CiscoASA.log"]

    def test_test_net_documentation_ranges_count_as_external(self):
        """ipaddress marks 203.0.113.0/24 private; the scenarios use it as an
        internet host, so the site's own prefixes decide instead."""
        feeds = dict(self._follow_up("203.0.113.9").to_vendor_feeds())
        assert list(feeds) == ["Kinetix_CiscoASA.log"]
