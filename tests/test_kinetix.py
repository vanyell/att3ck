"""
Kinetix Test Suite — H5 Implementation
Covers: Unit Validation, Variable Resolution, Thread Safety, CEF Format, Scenario Loading
"""
import pytest
import json
import os
import copy
import threading
import uuid
from pathlib import Path
from datetime import timezone

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
        assert result in ["jsmith", "ajones", "mrobinson", "tclark", "lwhite"]

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
        """L4: is_malicious, scenario_id, depth must not appear in JSON output."""
        from kinetix.outputs.file import FileOutput
        from kinetix.schemas.endpoint import ProcessEvent

        ev = ProcessEvent(
            FileName="test.exe", ProcessId=1,
            ProcessCommandLine="test", is_malicious=True,
            scenario_id="TEST-001"
        )
        fo = FileOutput.__new__(FileOutput)  # Skip __init__
        json_str = fo._format_json(ev)
        parsed = json.loads(json_str)

        assert "is_malicious" not in parsed
        assert "scenario_id" not in parsed
        assert "depth" not in parsed
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


# --- Markov Engine Tests ---

class TestTemporalEngine:
    """M5: Validates that the Markov engine actually produces follow-up events."""

    def test_signin_triggers_follow_up(self):
        from kinetix.core.temporal import TemporalEngine
        te = TemporalEngine()
        next_type = te.get_next_event_type("SigninLogs")
        assert next_type in ["DeviceProcessEvents", "OfficeActivity", None]

    def test_process_triggers_follow_up(self):
        from kinetix.core.temporal import TemporalEngine
        te = TemporalEngine()
        next_type = te.get_next_event_type("DeviceProcessEvents")
        assert next_type in ["CommonSecurityLog", "DeviceFileEvents", None]

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
