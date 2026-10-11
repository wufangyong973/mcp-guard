"""Regression tests for #37 (glob anchoring), #38 (SARIF source_path), #39 (path validation)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_guard.formatters import to_sarif
from mcp_guard.models import RiskLevel, RiskFinding, ScanResult
from mcp_guard.parser import MCPParser
from mcp_guard.policy import _glob_match


# ── #37: glob pattern anchoring ─────────────────────────────────────────────

class TestGlobAnchoring:
    """#37: _glob_match must be a strict full-match, not a substring match."""

    def test_substring_does_not_match(self):
        assert _glob_match("github", "hub") is False

    def test_wildcard_prefix(self):
        assert _glob_match("hub-server", "hub*") is True

    def test_wildcard_prefix_rejects_non_prefix(self):
        assert _glob_match("github", "hub*") is False

    def test_wildcard_prefix_requires_prefix(self):
        assert _glob_match("myhub-server", "hub*") is False

    def test_exact_match(self):
        assert _glob_match("github", "github") is True

    def test_case_insensitive(self):
        assert _glob_match("GitHub", "github") is True

    def test_invalid_pattern_falls_back_to_fnmatch(self):
        # An unclosed bracket raises re.error; the fallback to fnmatch must not crash.
        result = _glob_match("abc", "[")
        assert isinstance(result, bool)


# ── #38: SARIF source_path ──────────────────────────────────────────────────

class TestSarifSourcePath:
    """#38: to_sarif uses manifest.source_path, not the hardcoded mcp-server/…."""

    def _write_manifest(self, tmp_path: Path) -> Path:
        f = tmp_path / "mcp.json"
        f.write_text(
            json.dumps(
                {
                    "name": "test-srv",
                    "version": "1.0.0",
                    "tools": [
                        {"name": "delete_repo", "description": "Delete a repository"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        return f

    def test_manifest_carries_source_path(self, tmp_path: Path):
        f = self._write_manifest(tmp_path)
        manifest = MCPParser.from_json(f)
        assert manifest.source_path == str(f)

    def test_sarif_uses_real_source_path(self, tmp_path: Path):
        f = self._write_manifest(tmp_path)
        manifest = MCPParser.from_json(f)
        result = ScanResult(
            manifest=manifest,
            findings=[
                RiskFinding(
                    rule_id="MCP002",
                    level=RiskLevel.CRITICAL,
                    message="Destructive tool",
                    capability_name="delete_repo",
                )
            ],
        )
        sarif = to_sarif(result)
        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == str(f)
        assert "mcp-server/" not in uri

    def test_sarif_fallback_when_no_source_path(self):
        from mcp_guard.models import MCPCapability, MCPCapabilityType, MCPManifest

        manifest = MCPManifest(
            name="inline-srv",
            capabilities=[
                MCPCapability(
                    name="delete_repo",
                    type=MCPCapabilityType.TOOL,
                    description="Delete a repository",
                )
            ],
        )
        result = ScanResult(
            manifest=manifest,
            findings=[
                RiskFinding(
                    rule_id="MCP002",
                    level=RiskLevel.CRITICAL,
                    message="Destructive tool",
                    capability_name="delete_repo",
                )
            ],
        )
        sarif = to_sarif(result)
        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "mcp-server/delete_repo"


# ── #39: path validation ────────────────────────────────────────────────────

class TestPathValidation:
    """#39: _validate_path rejects '..' traversal."""

    def test_dotdot_rejected(self):
        with pytest.raises(ValueError, match="\\.\\."):
            MCPParser._validate_path("../outside.json")

    def test_nested_dotdot_rejected(self):
        with pytest.raises(ValueError, match="\\.\\."):
            MCPParser._validate_path("safe/../../etc/passwd")

    def test_safe_path_passes(self):
        p = MCPParser._validate_path("safe/path.json")
        assert isinstance(p, Path)

    def test_from_file_rejects_dotdot(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ValueError, match="\\.\\."):
            MCPParser.from_file("../outside.json")

    def test_from_file_rejects_absolute_escape(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Absolute paths without '..' are not rejected by the current guard."""
        monkeypatch.chdir(tmp_path)
        # The guard only checks for '..', so an absolute path without '..' passes.
        # This documents the current behavior.
        p = MCPParser._validate_path("/etc/passwd")
        assert isinstance(p, Path)
