from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from agent_latch import cli
from agent_latch.report import json_report, sarif_report
from agent_latch.rules import DependencyAuditError, audit_requirements, scan_project


def test_detects_dynamic_execution_and_shell_true(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        "import subprocess\n"
        "user_code = input()\n"
        "eval(user_code)\n"
        "subprocess.run(user_code, shell=True)\n",
        encoding="utf-8",
    )

    findings = scan_project(tmp_path)

    assert {finding.rule_id for finding in findings} >= {
        "AGENTLATCH-PY001",
        "AGENTLATCH-PY002",
    }
    assert all(finding.path == "agent.py" for finding in findings)


def test_detects_langchain_dataframe_agent_code_execution_capability(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        "from langchain_experimental.agents import create_pandas_dataframe_agent\n"
        "parser.add_argument('--allow-dangerous-code', action='store_true')\n"
        "agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=args.allow_dangerous_code)\n",
        encoding="utf-8",
    )

    findings = scan_project(tmp_path)

    code_execution = next(item for item in findings if item.rule_id == "AGENTLATCH-AG002")
    assert code_execution.line == 3
    assert code_execution.owasp == ("ASI05", "ASI02")
    assert "isolate execution" in code_execution.message


def test_secret_value_is_never_in_report_evidence(tmp_path: Path) -> None:
    secret = "sk_live_very_secret_value_123"
    (tmp_path / "settings.py").write_text(f'api_key = "{secret}"\n', encoding="utf-8")

    findings = scan_project(tmp_path)

    secret_finding = next(item for item in findings if item.rule_id == "AGENTLATCH-SEC001")
    assert secret not in secret_finding.evidence
    assert secret_finding.owasp == ("ASI03", "ASI04")


def test_skips_virtual_environment_and_oversized_files(tmp_path: Path) -> None:
    venv = tmp_path / ".venv" / "lib" / "bad.py"
    venv.parent.mkdir(parents=True)
    venv.write_text("eval('bad')\n", encoding="utf-8")
    huge = tmp_path / "large.py"
    huge.write_text("#" + ("x" * 1_000_001), encoding="utf-8")

    assert scan_project(tmp_path) == []


def test_json_and_sarif_reports_parse(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text("eval('x')\n", encoding="utf-8")
    findings = scan_project(tmp_path)

    parsed_json = json.loads(json_report(findings, str(tmp_path)))
    parsed_sarif = json.loads(sarif_report(findings, str(tmp_path)))
    assert parsed_json["finding_count"] == 1
    assert parsed_sarif["version"] == "2.1.0"
    assert parsed_sarif["runs"][0]["results"][0]["ruleId"] == "AGENTLATCH-PY001"


def test_dependency_audit_maps_advisories_without_installing_packages(
    tmp_path: Path, monkeypatch
) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.20.0\n", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return SimpleNamespace(
            returncode=1,
            stdout=json.dumps(
                [
                    {
                        "name": "requests",
                        "version": "2.20.0",
                        "vulns": [
                            {
                                "id": "PYSEC-TEST-1",
                                "aliases": ["CVE-2099-1234"],
                                "fix_versions": ["2.31.0"],
                            }
                        ],
                    }
                ]
            ),
            stderr="",
        )

    monkeypatch.setattr("agent_latch.rules.subprocess.run", fake_run)
    findings, manifest_count = audit_requirements(tmp_path)

    command = captured["command"]
    assert isinstance(command, list)
    assert "--no-deps" in command
    assert "--disable-pip" in command
    assert captured.get("shell") is not True
    assert captured["timeout"] == 180
    assert manifest_count == 1
    assert len(findings) == 1
    assert findings[0].rule_id == "AGENTLATCH-DEP001"
    assert findings[0].line == 1
    assert "CVE-2099-1234" in findings[0].message
    assert findings[0].owasp == ("ASI04",)
    assert findings[0].severity == "unknown"


def test_dependency_audit_deduplicates_same_package_advisory(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "requirements.txt").write_text("langchain==0.3.0\n", encoding="utf-8")
    duplicate_advisory = {
        "id": "PYSEC-2026-2192",
        "aliases": ["CVE-2026-55443"],
        "fix_versions": ["1.3.9"],
    }
    monkeypatch.setattr(
        "agent_latch.rules.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout=json.dumps(
                {
                    "dependencies": [
                        {
                            "name": "langchain",
                            "version": "0.3.0",
                            "vulns": [duplicate_advisory, duplicate_advisory],
                        }
                    ],
                    "fixes": [],
                }
            ),
            stderr="",
        ),
    )

    findings, _ = audit_requirements(tmp_path)

    assert len(findings) == 1
    assert findings[0].severity == "unknown"


def test_dependency_audit_accepts_current_pip_audit_object_schema(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.20.0\n", encoding="utf-8")
    monkeypatch.setattr(
        "agent_latch.rules.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "dependencies": [
                        {"name": "requests", "version": "2.32.0", "vulns": []}
                    ],
                    "fixes": [],
                }
            ),
            stderr="",
        ),
    )

    findings, manifest_count = audit_requirements(tmp_path)

    assert findings == []
    assert manifest_count == 1


def test_dependency_audit_reports_no_manifest_as_zero_coverage(tmp_path: Path) -> None:
    findings, manifest_count = audit_requirements(tmp_path)
    assert findings == []
    assert manifest_count == 0


def test_dependency_audit_handles_tool_failure_without_leaking_stderr(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.20.0\n", encoding="utf-8")
    monkeypatch.setattr(
        "agent_latch.rules.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0], returncode=2, stdout="", stderr="credential=private-token"
        ),
    )

    try:
        audit_requirements(tmp_path)
    except DependencyAuditError as exc:
        assert "private-token" not in str(exc)
    else:
        raise AssertionError("Expected a dependency audit error")


def test_interactive_flag_dispatches_to_guided_cli(monkeypatch) -> None:
    monkeypatch.setattr("sys.argv", ["agent-latch", "--interactive"])
    monkeypatch.setattr(cli, "interactive_main", lambda: 17)

    assert cli.main() == 17
