# Phase 3 unit tests for the Gemini agent loop.
# All Gemini API calls are mocked — no network, no real LLM.
import time
import uuid
from unittest.mock import MagicMock, patch

import pytest

import agent
from agent import (
    JOB_STATUS,
    MAX_ITERATIONS,
    build_report,
    build_system_prompt,
    run_agent,
)


# ---------------------------------------------------------------------------
# Helpers — synthesize Gemini-shaped response objects
# ---------------------------------------------------------------------------

def _make_part(text=None, fc_name=None, fc_args=None):
    """Build a single 'part' as returned in Gemini candidate.content.parts."""
    part = MagicMock()
    part.text = text  # may be None
    if fc_name is None:
        part.function_call = None
    else:
        fc = MagicMock()
        fc.name = fc_name
        fc.args = fc_args or {}
        part.function_call = fc
    return part


def _make_response(parts):
    response = MagicMock()
    candidate = MagicMock()
    candidate.content = MagicMock()
    candidate.content.parts = parts
    response.candidates = [candidate]
    return response


def _mock_model(responses):
    """Return a MagicMock model whose generate_content yields the given responses in order."""
    model = MagicMock()
    if isinstance(responses, list):
        model.generate_content = MagicMock(side_effect=responses)
    else:
        model.generate_content = MagicMock(return_value=responses)
    return model


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def file_meta():
    return {
        "filename": "sample.exe",
        "sha256": "a" * 64,
        "size_bytes": 4096,
        "extension": ".exe",
        "entropy": 7.8,
    }


@pytest.fixture(autouse=True)
def _clear_status():
    JOB_STATUS.clear()
    yield
    JOB_STATUS.clear()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_agent_completes_in_one_iteration(file_meta):
    """Mocked Gemini calls get_report on the very first turn — agent returns immediately."""
    response = _make_response([
        _make_part(text="Hash matched a known sample. Calling get_report."),
        _make_part(fc_name="get_report", fc_args={
            "verdict": "malicious",
            "confidence": 99,
            "threat_category": "trojan",
            "severity": "critical",
            "summary": "Known-bad SHA-256 hit in MalwareBazaar.",
            "key_indicators": ["Known hash"],
            "mitre_techniques": [],
            "recommended_action": "Quarantine",
            "iocs": {},
        }),
    ])
    model = _mock_model([response])

    with patch.object(agent, "build_model", return_value=model):
        result = run_agent("/tmp/sample", file_meta, "standard")

    assert result["verdict"] == "malicious"
    assert result["confidence"] == 99
    assert result["tools_called"] == 1
    assert result["mode"] == "standard"
    assert len(result["reasoning_chain"]["steps"]) == 1
    # Gemini was called exactly once
    assert model.generate_content.call_count == 1


def test_agent_loops_three_times_before_get_report(file_meta):
    """Agent calls 2 analysis tools then get_report on the 3rd turn."""
    responses = [
        _make_response([
            _make_part(text="Step 1: confirm true file type."),
            _make_part(fc_name="get_file_magic", fc_args={}),
        ]),
        _make_response([
            _make_part(text="Step 2: PE32+, inspect imports."),
            _make_part(fc_name="get_pe_imports", fc_args={}),
        ]),
        _make_response([
            _make_part(text="Step 3: enough evidence — verdict suspicious."),
            _make_part(fc_name="get_report", fc_args={
                "verdict": "suspicious",
                "confidence": 70,
                "threat_category": "unknown",
                "severity": "medium",
                "summary": "Imports look unusual but no smoking gun.",
                "key_indicators": ["odd imports"],
                "mitre_techniques": [],
                "recommended_action": "Further analysis needed",
                "iocs": {},
            }),
        ]),
    ]
    model = _mock_model(responses)

    fake_results = {
        "get_file_magic": {"magic_type": "PE32+ executable"},
        "get_pe_imports": {"dlls": ["kernel32.dll"], "suspicious_imports": []},
    }

    def fake_execute(name, params, file_path):
        return fake_results.get(name, {"ok": True})

    with patch.object(agent, "build_model", return_value=model), \
         patch.object(agent, "execute_tool", side_effect=fake_execute):
        result = run_agent("/tmp/sample", file_meta, "standard")

    assert result["tools_called"] == 3
    steps = result["reasoning_chain"]["steps"]
    assert len(steps) == 3
    assert steps[0]["tool_called"].startswith("get_file_magic(")
    assert steps[1]["tool_called"].startswith("get_pe_imports(")
    assert steps[2]["tool_called"] == "get_report(...)"
    assert result["verdict"] == "suspicious"
    assert model.generate_content.call_count == 3


def test_agent_hits_max_iterations(file_meta):
    """Agent never calls get_report — loop force-terminates with incomplete_analysis=True."""
    # Same response every turn: text + a non-terminating tool call.
    def _every_turn():
        return _make_response([
            _make_part(text="Still investigating."),
            _make_part(fc_name="get_file_magic", fc_args={}),
        ])

    model = MagicMock()
    model.generate_content = MagicMock(side_effect=lambda *a, **kw: _every_turn())

    with patch.object(agent, "build_model", return_value=model), \
         patch.object(agent, "execute_tool", return_value={"magic_type": "PE32+"}):
        result = run_agent("/tmp/sample", file_meta, "standard")

    assert result["verdict"] == "unknown"
    assert result["confidence"] == 0
    assert result.get("incomplete_analysis") is True
    assert result["tools_called"] == MAX_ITERATIONS["standard"]
    assert len(result["reasoning_chain"]["steps"]) == MAX_ITERATIONS["standard"]
    assert model.generate_content.call_count == MAX_ITERATIONS["standard"]


def test_agent_nudges_on_no_tool_call(file_meta):
    """First turn returns text-only — agent injects a nudge and continues."""
    responses = [
        # Turn 1: text only, no function_call
        _make_response([_make_part(text="Hmm, let me think about this...")]),
        # Turn 2: nudged into committing
        _make_response([
            _make_part(text="OK, committing benign verdict."),
            _make_part(fc_name="get_report", fc_args={
                "verdict": "benign",
                "confidence": 90,
                "summary": "Nothing suspicious found.",
            }),
        ]),
    ]
    model = _mock_model(responses)

    with patch.object(agent, "build_model", return_value=model):
        result = run_agent("/tmp/sample", file_meta, "standard")

    assert result["verdict"] == "benign"
    assert result["tools_called"] == 2  # iterations counter increments on the nudge turn
    # Nudge turn produced no chain entry — only the get_report turn did
    assert len(result["reasoning_chain"]["steps"]) == 1
    assert model.generate_content.call_count == 2


def test_reasoning_chain_step_count_matches_iterations(file_meta):
    """Each tool-calling iteration produces exactly one reasoning_chain step in order."""
    responses = [
        _make_response([
            _make_part(text="step 1 reasoning"),
            _make_part(fc_name="get_file_magic", fc_args={}),
        ]),
        _make_response([
            _make_part(text="step 2 reasoning"),
            _make_part(fc_name="get_entropy", fc_args={}),
        ]),
        _make_response([
            _make_part(text="step 3 reasoning"),
            _make_part(fc_name="extract_strings", fc_args={"min_length": 8}),
        ]),
        _make_response([
            _make_part(text="step 4 reasoning"),
            _make_part(fc_name="get_report", fc_args={
                "verdict": "benign",
                "confidence": 95,
                "summary": "Looks clean.",
            }),
        ]),
    ]
    model = _mock_model(responses)

    with patch.object(agent, "build_model", return_value=model), \
         patch.object(agent, "execute_tool", return_value={"ok": True}):
        result = run_agent("/tmp/sample", file_meta, "standard")

    steps = result["reasoning_chain"]["steps"]
    assert len(steps) == 4
    assert [s["step_number"] for s in steps] == [1, 2, 3, 4]
    assert all(s["reasoning"].startswith("step ") for s in steps)
    assert steps[0]["tool_called"].startswith("get_file_magic(")
    assert steps[1]["tool_called"].startswith("get_entropy(")
    assert steps[2]["tool_called"].startswith("extract_strings(")
    assert "min_length" in steps[2]["tool_called"]
    assert steps[3]["tool_called"] == "get_report(...)"
    # result_summary is bounded
    for s in steps:
        assert len(s["result_summary"]) <= 200


def test_build_report_has_all_section_8_1_keys():
    """build_report() must populate every field required by PRD Section 8.1."""
    verdict_params = {
        "verdict": "malicious",
        "confidence": 95,
        "threat_category": "trojan",
        "severity": "high",
        "summary": "Test summary.",
        "key_indicators": ["one", "two"],
        "mitre_techniques": [
            {"id": "T1027", "name": "Obfuscated Files", "tactic": "Defense Evasion", "evidence": "x"},
        ],
        "recommended_action": "Quarantine",
        "iocs": {"ips": ["1.2.3.4"], "urls": ["http://x"], "domains": []},
    }
    reasoning_chain = [
        {"step_number": 1, "reasoning": "r1", "tool_called": "t1()", "result_summary": "s1"},
        {"step_number": 2, "reasoning": "r2", "tool_called": "t2()", "result_summary": "s2"},
    ]
    file_meta = {
        "filename": "x.exe", "sha256": "0" * 64, "size_bytes": 1024,
        "extension": ".exe", "entropy": 6.5,
    }
    start = time.time() - 30

    report = build_report(
        verdict_params=verdict_params,
        reasoning_chain=reasoning_chain,
        file_meta=file_meta,
        mode="deep_scan",
        iterations=7,
        start_time=start,
    )

    required = {
        "job_id", "mode", "verdict", "confidence", "threat_category",
        "severity", "summary", "key_indicators", "mitre_techniques",
        "recommended_action", "iocs", "tools_called", "analysis_time_seconds",
    }
    assert required.issubset(report.keys())
    assert report["mode"] == "deep_scan"
    assert report["verdict"] == "malicious"
    assert report["confidence"] == 95
    assert report["tools_called"] == 7
    assert report["analysis_time_seconds"] >= 25  # ~30s elapsed
    # Reasoning chain comes through unchanged
    assert report["reasoning_chain"]["steps"] == reasoning_chain
    # job_id is a valid UUID
    uuid.UUID(report["job_id"])


def test_build_report_fills_defaults_for_missing_fields():
    """Force-terminate path passes minimal verdict params — defaults must fill in."""
    report = build_report(
        verdict_params={"verdict": "unknown", "confidence": 0,
                        "summary": "incomplete", "incomplete_analysis": True},
        reasoning_chain=[],
        file_meta={"filename": "x"},
        mode="standard",
        iterations=8,
        start_time=time.time(),
    )
    assert report["threat_category"] == "unknown"
    assert report["severity"] == "low"
    assert report["recommended_action"] == "Further analysis needed"
    assert report["key_indicators"] == []
    assert report["mitre_techniques"] == []
    assert report["iocs"] == {}
    assert report["incomplete_analysis"] is True


def test_build_system_prompt_mentions_mode_limit():
    """System prompt must explicitly state the call-limit for the active mode."""
    standard = build_system_prompt("standard")
    deep = build_system_prompt("deep_scan")

    assert "standard" in standard
    assert "8" in standard  # tool-call ceiling
    assert "Rules" in standard
    # All seven rules numbered 1..7 must appear
    for i in range(1, 8):
        assert f"\n{i}." in standard

    assert "deep_scan" in deep
    assert "20" in deep


def test_build_system_prompt_rejects_unknown_mode():
    with pytest.raises(ValueError):
        build_system_prompt("turbo")


def test_job_status_is_updated_during_run(file_meta):
    """Live JOB_STATUS dict should be populated while the agent is running."""
    response = _make_response([
        _make_part(text="done"),
        _make_part(fc_name="get_report", fc_args={
            "verdict": "benign", "confidence": 80, "summary": "ok",
        }),
    ])
    model = _mock_model([response])

    file_meta_with_id = {**file_meta, "job_id": "fixed-job-id-123"}

    with patch.object(agent, "build_model", return_value=model):
        run_agent("/tmp/sample", file_meta_with_id, "standard")

    assert "fixed-job-id-123" in JOB_STATUS
    status = JOB_STATUS["fixed-job-id-123"]
    assert "step" in status
    assert "action" in status
    assert "elapsed_seconds" in status
    assert isinstance(status["elapsed_seconds"], int)


def test_run_agent_rejects_unknown_mode(file_meta):
    with pytest.raises(ValueError):
        run_agent("/tmp/sample", file_meta, "ultra_deep")


def test_malsight_tools_contains_all_30_declarations():
    """Sanity-check the tool catalog matches the PRD."""
    names = [fd.name for fd in agent.malsight_tools.function_declarations]
    expected = {
        "check_malwarebazaar", "check_virustotal", "check_ip_reputation",
        "check_domain_reputation",
        "get_file_magic", "get_entropy", "extract_strings", "get_pe_imports",
        "get_pe_sections", "detect_packer", "check_digital_signature",
        "get_compile_timestamp", "analyze_pdf_structure", "deobfuscate_script",
        "run_sandbox", "capture_memory_dump", "monitor_filesystem",
        "get_dropped_files",
        "scan_pe_headers", "extract_strings_from_memory", "detect_shellcode",
        "get_memory_entropy", "analyze_injected_pe", "run_yara",
        "detect_anti_debug", "detect_anti_vm", "detect_anti_sandbox",
        "extract_iocs", "get_report",
    }
    assert set(names) == expected
    # No duplicates
    assert len(names) == len(set(names))
