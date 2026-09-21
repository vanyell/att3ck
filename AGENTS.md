# AGENTS.md

## Critical: Python environment

Always use `./venv/bin/python` or activate the venv first. `python3 main.py` without the venv will fail on missing dependencies. The venv is created by `bash setup_env.sh`.

```bash
source venv/bin/activate
# or
./venv/bin/python main.py --scenario scenarios/ransomware_v1.json --duration 10
```

## Run commands

| Task | Command |
|------|---------|
| Run simulation | `./venv/bin/python main.py` |
| Single scenario | `./venv/bin/python main.py --scenario scenarios/name.json --duration 30` |
| Tests | `./venv/bin/python -m pytest -v` |
| Single test class | `./venv/bin/python -m pytest tests/test_kinetix.py -k "TestClassName"` |
| Verify engine | `./venv/bin/python scripts/verify_engine.py` |

No linter, formatter, or typecheck tool is configured in pyproject.toml. Run tests to verify changes.

## Architecture quick-reference

- **Entry point**: `main.py` (Click CLI). Builds event registry, creates `KinetixEngine`, runs scenarios.
- **Scenarios**: JSON files in `scenarios/`. Each defines stages with events. Events use `source` + `event_type` to select a Pydantic schema.
- **Schema registry**: Built in `main.py:_build_event_registry()`. Maps `(source, event_type)` → Pydantic model class.
- **Table mapping**: `kinetix/outputs/file.py:_map_to_table_name()` maps schema class → Sentinel table name for JSON output files.
- **Variables**: `kinetix/core/vars.py` resolves `{{PLACEHOLDERS}}`. `{{PERSONA_*}}` are session-stable (same identity across all events in one run). `{{RANDOM_*}}` produce new values per call.
- **Output**: Four formats written simultaneously (JSON per-table, CEF unified, Syslog RFC 3164, Windows EVT XML). All rotate at 10MB.
- **Linux/macOS events** are excluded from EVT output (syslog only).

## Adding a new schema

1. Create model in `kinetix/schemas/` subclassing `BaseLogEvent` with `source` and `event_type` Literals
2. Register in `main.py:_build_event_registry()`
3. Add table mapping in `kinetix/outputs/file.py:_map_to_table_name()`
4. If multi-format output needed, implement `to_syslog()` and/or `to_evt()` on the model

## Scenario JSON gotchas

- `data` key auto-flattens into top-level fields — you can put fields inside `data` or at the top level
- `multiply` replicates the event N times with unique template resolution per instance
- `killchain_phase` uses lowercase-hyphenated values (e.g., `initial-access`, `credential-access`)

## Testing

All tests live in `tests/test_kinetix.py`. Test classes cover: schema validation, variable resolution, multiply uniqueness, output formats (CEF/Syslog/EVT), scenario loading, Markov transitions, killchain propagation, persona integration, detection annotations.

Python >=3.12 required. Dependencies: pydantic, orjson, numpy, click, rich.
