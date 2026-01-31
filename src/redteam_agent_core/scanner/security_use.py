"""
Integration with security-use scanner.

Repository: https://github.com/security-use/security-use

This module wraps the security-use scanner to:
1. Clone/update the scanner repository
2. Run scans against target applications
3. Parse results into our SecurityIssue model
"""

import asyncio
import json
import subprocess
from pathlib import Path
from typing import AsyncIterator

from ..models.vulnerability import SecurityIssue, Severity


class SecurityUseScanner:
    """
    Wrapper for the security-use scanner.

    The scanner is cloned from https://github.com/security-use/security-use
    and executed against target applications.
    """

    REPO_URL = "https://github.com/security-use/security-use.git"

    def __init__(self, install_path: Path | None = None):
        """
        Initialize the scanner.

        Args:
            install_path: Where to clone/find the security-use repo.
                         Defaults to ~/.redteam-agent/security-use
        """
        self.install_path = install_path or Path.home() / ".redteam-agent" / "security-use"
        self._ensure_installed()

    def _ensure_installed(self) -> None:
        """Clone or update the security-use repository."""
        if not self.install_path.exists():
            self.install_path.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", self.REPO_URL, str(self.install_path)],
                check=True,
                capture_output=True,
            )
        else:
            # Pull latest
            subprocess.run(
                ["git", "-C", str(self.install_path), "pull"],
                check=True,
                capture_output=True,
            )

    async def scan_url(
        self,
        target_url: str,
        scan_type: str = "full",
    ) -> list[SecurityIssue]:
        """
        Scan a URL for vulnerabilities.

        Args:
            target_url: The URL to scan
            scan_type: Type of scan - "quick", "standard", or "full"

        Returns:
            List of SecurityIssue objects found
        """
        # Run security-use scanner
        # Actual command depends on security-use CLI interface
        cmd = [
            "python", "-m", "security_use",
            "--target", target_url,
            "--type", scan_type,
            "--output", "json",
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(self.install_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise RuntimeError(f"security-use scan failed: {stderr.decode()}")

        return self._parse_results(stdout.decode())

    async def scan_repository(
        self,
        repo_path: Path,
        scan_type: str = "full",
    ) -> list[SecurityIssue]:
        """
        Scan a local repository for vulnerabilities (SAST).

        Args:
            repo_path: Path to the repository to scan
            scan_type: Type of scan - "quick", "standard", or "full"

        Returns:
            List of SecurityIssue objects found
        """
        cmd = [
            "python", "-m", "security_use",
            "--repo", str(repo_path),
            "--type", scan_type,
            "--output", "json",
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(self.install_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise RuntimeError(f"security-use scan failed: {stderr.decode()}")

        return self._parse_results(stdout.decode())

    async def stream_scan(
        self,
        target_url: str,
        scan_type: str = "full",
    ) -> AsyncIterator[SecurityIssue]:
        """
        Stream scan results as they are found.

        Useful for real-time updates to the frontend.
        """
        cmd = [
            "python", "-m", "security_use",
            "--target", target_url,
            "--type", scan_type,
            "--output", "jsonl",  # JSON Lines for streaming
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(self.install_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async for line in process.stdout:
            if line.strip():
                try:
                    data = json.loads(line.decode())
                    yield self._parse_single_result(data)
                except json.JSONDecodeError:
                    continue

        await process.wait()

    def _parse_results(self, output: str) -> list[SecurityIssue]:
        """Parse JSON output from security-use into SecurityIssue objects."""
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []

        issues = []
        for item in data.get("vulnerabilities", []):
            issues.append(self._parse_single_result(item))

        return issues

    def _parse_single_result(self, item: dict) -> SecurityIssue:
        """Parse a single vulnerability finding."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        return SecurityIssue(
            id=item.get("id", "unknown"),
            severity=severity_map.get(item.get("severity", "medium").lower(), Severity.MEDIUM),
            category=item.get("category", "unknown"),
            title=item.get("title", "Unknown vulnerability"),
            description=item.get("description", ""),
            file_path=item.get("file_path"),
            line_number=item.get("line_number"),
            code_snippet=item.get("code_snippet"),
            cwe_id=item.get("cwe_id"),
            cvss_score=item.get("cvss_score"),
            remediation_hint=item.get("remediation", ""),
            confidence=item.get("confidence", 1.0),
        )

    def get_version(self) -> str:
        """Get the installed version of security-use."""
        result = subprocess.run(
            ["git", "-C", str(self.install_path), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
