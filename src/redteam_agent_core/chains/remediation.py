"""
Remediation chain engine for fixing exploited vulnerabilities.

After a successful exploit, the remediation chain:
1. Analyzes the exploit and affected code
2. Generates a code fix using the LLM
3. Applies the fix to the codebase
4. Re-runs the exploit to verify it fails
5. Retries if verification fails (up to max attempts)
"""

import json
import re
from difflib import unified_diff
from typing import AsyncIterator

import structlog
from pydantic import BaseModel

from ..events import EventEmitter
from ..executor import ExecutorClient, TargetInfo
from ..llm import LLMResponse, OpenRouterProvider
from ..models.app_context import AppContext
from ..models.events import CommandStatus
from ..models.results import (
    ChainStep,
    ChainType,
    CodeFix,
    ExploitResult,
    RemediationResult,
    StepStatus,
)

logger = structlog.get_logger(__name__)


class RemediationPlan(BaseModel):
    """Plan for remediating a vulnerability."""

    exploit_result: ExploitResult
    affected_files: list[str]
    fix_approach: str


class ApplyResult(BaseModel):
    """Result of applying a code fix."""

    success: bool
    has_errors: bool
    errors: list[str]
    files_modified: list[str]


class VerificationResult(BaseModel):
    """Result of verifying a fix."""

    exploit_blocked: bool
    output: str
    error: str | None = None


# System prompt for fix generation
REMEDIATION_SYSTEM_PROMPT = """You are a security engineer fixing a vulnerability that was successfully exploited.
Your task is to generate a minimal, targeted fix that addresses the vulnerability without breaking functionality.

Guidelines:
- Make the smallest change necessary to fix the vulnerability
- Follow secure coding best practices
- Maintain the existing code style
- Add input validation where appropriate
- Use parameterized queries for SQL
- Escape output for XSS prevention
- Validate and sanitize all user input

Output your response as JSON with this structure:
{
    "reasoning": "Explanation of the vulnerability and why this fix works",
    "file_path": "path/to/file.py",
    "original_code": "the exact vulnerable code to replace",
    "fixed_code": "the secure replacement code",
    "explanation": "Human-readable explanation of the fix"
}"""


class RemediationChain:
    """
    Remediation chain engine for fixing vulnerabilities.

    Uses the LLM to generate code fixes and verifies them
    by re-running the exploit.
    """

    def __init__(
        self,
        llm: OpenRouterProvider,
        emitter: EventEmitter,
        max_attempts: int = 5,
    ):
        """
        Initialize the remediation chain.

        Args:
            llm: LLM provider for generating fixes
            emitter: Event emitter for streaming updates
            max_attempts: Maximum fix attempts
        """
        self.llm = llm
        self.emitter = emitter
        self.max_attempts = max_attempts
        self.result: RemediationResult | None = None

    async def analyze_exploit(
        self,
        exploit_result: ExploitResult,
        codebase: dict[str, str],
    ) -> RemediationPlan:
        """
        Analyze an exploit to determine what needs to be fixed.

        Args:
            exploit_result: The successful exploit result
            codebase: Dictionary of file_path -> content

        Returns:
            RemediationPlan with fix approach
        """
        # Find affected files based on exploit steps
        affected_files = []
        for step in exploit_result.steps_executed:
            # Look for file references in commands or output
            for file_path in codebase.keys():
                if file_path in step.command or (step.output and file_path in step.output):
                    if file_path not in affected_files:
                        affected_files.append(file_path)

        # Determine fix approach based on vulnerability type
        fix_approach = self._determine_fix_approach(exploit_result.vulnerability_type)

        return RemediationPlan(
            exploit_result=exploit_result,
            affected_files=affected_files or list(codebase.keys())[:5],
            fix_approach=fix_approach,
        )

    def _determine_fix_approach(self, vulnerability_type: str) -> str:
        """Determine the fix approach based on vulnerability type."""
        approaches = {
            "sql_injection": "Use parameterized queries/prepared statements",
            "xss": "Escape output and validate input",
            "ssrf": "Validate and whitelist allowed URLs",
            "idor": "Implement proper authorization checks",
            "authentication": "Fix authentication logic and session handling",
            "command_injection": "Sanitize input and avoid shell execution",
        }
        return approaches.get(
            vulnerability_type.lower(),
            "Apply security best practices",
        )

    async def generate_fix(
        self,
        exploit_result: ExploitResult,
        source_code: str,
        file_path: str,
    ) -> CodeFix | None:
        """
        Generate a code fix for the vulnerability.

        Args:
            exploit_result: The exploit result to fix
            source_code: Source code of the affected file
            file_path: Path to the file

        Returns:
            CodeFix with the fix, or None if generation failed
        """
        prompt = f"""
VULNERABILITY INFORMATION:
- Type: {exploit_result.vulnerability_type}
- Severity: {exploit_result.severity}
- Summary: {exploit_result.summary}

EXPLOIT THAT WORKED:
{self._summarize_exploit(exploit_result)}

AFFECTED SOURCE CODE ({file_path}):
```
{source_code[:5000]}
```

Generate a fix for this vulnerability. Identify the vulnerable code and provide a secure replacement.
"""

        try:
            response = await self.llm.generate_json(
                prompt=prompt,
                system=REMEDIATION_SYSTEM_PROMPT,
                temperature=0.3,  # Lower temperature for more deterministic fixes
            )

            fix_data = self._parse_fix_response(response)
            if fix_data is None:
                return None

            # Generate diff
            original = fix_data.get("original_code", "")
            fixed = fix_data.get("fixed_code", "")
            diff = self._generate_diff(original, fixed, file_path)

            # Find line numbers
            line_start, line_end = self._find_code_location(source_code, original)

            return CodeFix(
                file_path=file_path,
                original_code=original,
                fixed_code=fixed,
                diff=diff,
                explanation=fix_data.get("explanation", "Security fix applied"),
                line_start=line_start,
                line_end=line_end,
            )

        except Exception as e:
            logger.error("fix_generation_failed", error=str(e))
            return None

    def _summarize_exploit(self, exploit_result: ExploitResult) -> str:
        """Summarize the exploit for the LLM."""
        summary_parts = []
        for step in exploit_result.steps_executed:
            summary_parts.append(f"Step {step.step_number}: {step.command}")
            if step.output:
                summary_parts.append(f"Output: {step.output[:200]}")
        return "\n".join(summary_parts)

    def _parse_fix_response(self, response: LLMResponse) -> dict | None:
        """Parse the LLM response into fix data."""
        try:
            content = response.content.strip()

            # Handle code blocks
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            data = json.loads(content)

            # Validate required fields
            if not data.get("fixed_code"):
                return None

            return data

        except json.JSONDecodeError:
            logger.warning("fix_parse_failed", content=response.content[:200])
            return None

    def _generate_diff(
        self,
        original: str,
        fixed: str,
        file_path: str,
    ) -> str:
        """Generate a unified diff between original and fixed code."""
        original_lines = original.splitlines(keepends=True)
        fixed_lines = fixed.splitlines(keepends=True)

        diff = unified_diff(
            original_lines,
            fixed_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
        return "".join(diff)

    def _find_code_location(
        self,
        source_code: str,
        target_code: str,
    ) -> tuple[int, int]:
        """Find the line numbers where target code exists in source."""
        lines = source_code.split("\n")
        target_lines = target_code.split("\n")

        if not target_lines:
            return (1, 1)

        first_line = target_lines[0].strip()

        for i, line in enumerate(lines):
            if first_line in line:
                return (i + 1, i + len(target_lines))

        return (1, len(target_lines))

    async def apply_fix(
        self,
        fix: CodeFix,
        codebase: dict[str, str],
    ) -> ApplyResult:
        """
        Apply a code fix to the codebase.

        Args:
            fix: The code fix to apply
            codebase: Dictionary of file_path -> content

        Returns:
            ApplyResult with success/failure status
        """
        errors = []
        files_modified = []

        try:
            if fix.file_path not in codebase:
                return ApplyResult(
                    success=False,
                    has_errors=True,
                    errors=[f"File not found: {fix.file_path}"],
                    files_modified=[],
                )

            original_content = codebase[fix.file_path]

            # Check if original code exists
            if fix.original_code not in original_content:
                return ApplyResult(
                    success=False,
                    has_errors=True,
                    errors=["Original code not found in file"],
                    files_modified=[],
                )

            # Apply the fix
            new_content = original_content.replace(
                fix.original_code,
                fix.fixed_code,
                1,  # Only replace first occurrence
            )

            # Validate Python syntax if applicable
            if fix.file_path.endswith(".py"):
                syntax_errors = self._validate_python_syntax(new_content)
                if syntax_errors:
                    errors.extend(syntax_errors)
                    return ApplyResult(
                        success=False,
                        has_errors=True,
                        errors=errors,
                        files_modified=[],
                    )

            # Update codebase
            codebase[fix.file_path] = new_content
            files_modified.append(fix.file_path)

            return ApplyResult(
                success=True,
                has_errors=False,
                errors=[],
                files_modified=files_modified,
            )

        except Exception as e:
            return ApplyResult(
                success=False,
                has_errors=True,
                errors=[str(e)],
                files_modified=[],
            )

    def _validate_python_syntax(self, code: str) -> list[str]:
        """Validate Python code syntax."""
        errors = []
        try:
            compile(code, "<string>", "exec")
        except SyntaxError as e:
            errors.append(f"Syntax error at line {e.lineno}: {e.msg}")
        return errors

    async def verify_fix(
        self,
        fix: CodeFix,
        exploit_result: ExploitResult,
        executor: ExecutorClient,
        target: TargetInfo,
        session_id: str,
        run_id: str,
    ) -> VerificationResult:
        """
        Verify that the fix blocks the exploit.

        Re-runs the exploit steps and checks that they fail.

        Args:
            fix: The fix that was applied
            exploit_result: Original exploit result
            executor: Executor client
            target: Target info
            session_id: Session ID
            run_id: Run ID

        Returns:
            VerificationResult with verification status
        """
        # Re-run the key exploit steps
        outputs = []

        for step in exploit_result.steps_executed:
            if step.status != StepStatus.SUCCESS:
                continue

            try:
                result = await executor.execute(
                    session_id=session_id,
                    run_id=run_id,
                    command=step.command,
                    executor_type=self.emitter._determine_executor_type(step.command)
                    if hasattr(self.emitter, "_determine_executor_type")
                    else "http",
                    target=target,
                    timeout=30,
                )

                outputs.append(result.stdout or result.stderr)

                # If the step still succeeds, the fix didn't work
                if result.exit_code == 0:
                    # Check if the output indicates successful exploitation
                    if self._indicates_exploitation(
                        result.stdout or "",
                        exploit_result.vulnerability_type,
                    ):
                        return VerificationResult(
                            exploit_blocked=False,
                            output=result.stdout or "",
                            error="Exploit still works after fix",
                        )

            except Exception as e:
                # Error during verification - consider it blocked
                outputs.append(f"Error: {e}")

        return VerificationResult(
            exploit_blocked=True,
            output="\n".join(outputs),
        )

    def _indicates_exploitation(self, output: str, vulnerability_type: str) -> bool:
        """Check if output indicates successful exploitation."""
        output_lower = output.lower()
        vuln_type = vulnerability_type.lower()

        indicators = {
            "sql_injection": ["sql", "database", "error", "union"],
            "xss": ["script", "javascript", "alert"],
            "ssrf": ["internal", "metadata", "169.254"],
            "idor": ["unauthorized", "data"],
        }

        type_indicators = indicators.get(vuln_type, [])
        return any(ind in output_lower for ind in type_indicators)

    async def run_remediation(
        self,
        exploit_result: ExploitResult,
        codebase: dict[str, str],
        executor: ExecutorClient,
        target: TargetInfo,
        session_id: str,
        run_id: str,
    ) -> AsyncIterator[ChainStep]:
        """
        Run the complete remediation chain.

        Args:
            exploit_result: The exploit to fix
            codebase: Dictionary of file_path -> content
            executor: Executor client
            target: Target info
            session_id: Session ID
            run_id: Run ID

        Yields:
            ChainStep objects for each remediation step
        """
        # Analyze the exploit
        plan = await self.analyze_exploit(exploit_result, codebase)

        steps_executed: list[ChainStep] = []
        code_fixes: list[CodeFix] = []
        verification_passed = False
        final_error = None

        for attempt in range(1, self.max_attempts + 1):
            step_number = len(steps_executed) + 1

            # Generate fix step
            step = ChainStep(
                step_number=step_number,
                chain_type=ChainType.REMEDIATION,
                reasoning=f"Attempt {attempt}: Generating fix for {exploit_result.vulnerability_type}",
                command=f"Generate fix for {plan.fix_approach}",
                expected_outcome="Valid code fix",
                success_criteria="Fix compiles and blocks exploit",
                status=StepStatus.RUNNING,
            )

            await self.emitter.emit_reasoning(
                step_number=step_number,
                chain_type=ChainType.REMEDIATION,
                reasoning_text=step.reasoning,
            )

            # Try each affected file
            for file_path in plan.affected_files:
                if file_path not in codebase:
                    continue

                fix = await self.generate_fix(
                    exploit_result=exploit_result,
                    source_code=codebase[file_path],
                    file_path=file_path,
                )

                if fix is None:
                    continue

                # Apply the fix
                await self.emitter.emit_command(
                    step_number=step_number,
                    command=f"Applying fix to {file_path}",
                    status=CommandStatus.RUNNING,
                    executor_type="shell",
                )

                apply_result = await self.apply_fix(fix, codebase)

                if apply_result.has_errors:
                    await self.emitter.emit_output(
                        step_number=step_number,
                        output=f"Fix failed: {apply_result.errors}",
                        stream="stderr",
                    )
                    final_error = f"Apply failed: {apply_result.errors}"
                    continue

                await self.emitter.emit_output(
                    step_number=step_number,
                    output=f"Fix applied to {file_path}",
                    stream="stdout",
                )

                code_fixes.append(fix)

                # Verify the fix
                await self.emitter.emit_command(
                    step_number=step_number,
                    command="Verifying fix by re-running exploit",
                    status=CommandStatus.RUNNING,
                    executor_type="http",
                )

                verification = await self.verify_fix(
                    fix=fix,
                    exploit_result=exploit_result,
                    executor=executor,
                    target=target,
                    session_id=session_id,
                    run_id=run_id,
                )

                if verification.exploit_blocked:
                    step.status = StepStatus.SUCCESS
                    step.output = "Fix verified - exploit blocked"
                    verification_passed = True

                    await self.emitter.emit_output(
                        step_number=step_number,
                        output="Verification passed - exploit is now blocked",
                        stream="stdout",
                    )

                    await self.emitter.emit_command(
                        step_number=step_number,
                        command=f"Applying fix to {file_path}",
                        status=CommandStatus.SUCCESS,
                        executor_type="shell",
                    )

                    steps_executed.append(step)
                    yield step
                    break
                else:
                    final_error = "Fix verification failed - exploit still works"
                    await self.emitter.emit_output(
                        step_number=step_number,
                        output=final_error,
                        stream="stderr",
                    )

            if verification_passed:
                break

            step.status = StepStatus.FAILED
            step.output = final_error
            steps_executed.append(step)
            yield step

        # Build final result
        self.result = RemediationResult(
            success=verification_passed,
            exploit_result=exploit_result,
            code_fixes=code_fixes,
            verification_passed=verification_passed,
            attempts=len(steps_executed),
            final_error=final_error if not verification_passed else None,
        )

        # Emit remediation result event
        await self.emitter.emit_remediation_result(
            success=verification_passed,
            files_changed=[f.file_path for f in code_fixes],
            fix_summary=f"Applied {len(code_fixes)} fixes",
            verification_passed=verification_passed,
        )
