"""Tests for exploit and remediation chains."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from redteam_agent_core.chains import ExploitChain, RemediationChain
from redteam_agent_core.events import EventEmitter
from redteam_agent_core.executor import ExecutorClient, TargetInfo
from redteam_agent_core.llm import LLMResponse, OpenRouterProvider
from redteam_agent_core.models.app_context import AppContext, ArchitectureInfo, TechStackInfo
from redteam_agent_core.models.results import ChainStep, ChainType, CodeFix, ExploitResult, StepStatus
from redteam_agent_core.models.vulnerability import SecurityIssue, Severity, VulnerabilityKnowledgeBase


@pytest.fixture
def mock_llm():
    """Create a mock LLM provider."""
    llm = MagicMock(spec=OpenRouterProvider)
    return llm


@pytest.fixture
def mock_emitter():
    """Create a mock event emitter."""
    emitter = MagicMock(spec=EventEmitter)
    emitter.emit_reasoning = AsyncMock()
    emitter.emit_command = AsyncMock()
    emitter.emit_output = AsyncMock()
    emitter.emit_exploit_result = AsyncMock()
    emitter.emit_remediation_result = AsyncMock()
    return emitter


@pytest.fixture
def mock_executor():
    """Create a mock executor client."""
    executor = MagicMock(spec=ExecutorClient)
    return executor


@pytest.fixture
def sample_vulnerability():
    """Create a sample vulnerability."""
    return SecurityIssue(
        id="vuln-001",
        severity=Severity.HIGH,
        category="sql_injection",
        title="SQL Injection in login",
        description="User input not sanitized in login query",
        file_path="app/auth.py",
        line_number=42,
        cwe_id="CWE-89",
        remediation_hint="Use parameterized queries",
    )


@pytest.fixture
def sample_app_context():
    """Create a sample app context."""
    return AppContext(
        app_name="TestApp",
        app_description="Test application",
        app_url="https://app.example.com",
        tech_stack=TechStackInfo(
            languages=["python"],
            frameworks=["fastapi"],
            databases=["postgresql"],
        ),
        architecture=ArchitectureInfo(),
        gcp_project_id="test-project",
        gcp_region="us-central1",
        gcp_service_name="test-service",
        gcp_container_url="https://test-service.run.app",
        github_org="test-org",
        github_repo="test-repo",
        user_email="test@example.com",
        session_id="session-1",
        run_id="run-1",
    )


@pytest.fixture
def sample_knowledge_base():
    """Create a sample knowledge base."""
    return VulnerabilityKnowledgeBase(
        vulnerabilities=[],
        crawled_at="2024-01-01T00:00:00",
        sources=["nvd"],
    )


class TestExploitChain:
    """Tests for ExploitChain."""

    def test_init(self, mock_llm, mock_emitter):
        """Test chain initialization."""
        chain = ExploitChain(mock_llm, mock_emitter, max_steps=30)
        assert chain.max_steps == 30
        assert chain.result is None

    def test_get_attack_vectors_sql_injection(self, mock_llm, mock_emitter, sample_vulnerability):
        """Test attack vector generation for SQL injection."""
        chain = ExploitChain(mock_llm, mock_emitter)
        vectors = chain._get_attack_vectors(sample_vulnerability)

        assert len(vectors) > 0
        assert "UNION-based injection" in vectors
        assert "Boolean-based blind injection" in vectors

    def test_get_attack_vectors_xss(self, mock_llm, mock_emitter):
        """Test attack vector generation for XSS."""
        vuln = SecurityIssue(
            id="xss-001",
            severity=Severity.MEDIUM,
            category="xss",
            title="XSS vulnerability",
            description="User input reflected in page",
            remediation_hint="Escape output",
        )

        chain = ExploitChain(mock_llm, mock_emitter)
        vectors = chain._get_attack_vectors(vuln)

        assert "Reflected XSS via URL parameter" in vectors
        assert "Stored XSS via form input" in vectors

    def test_determine_executor_type(self, mock_llm, mock_emitter):
        """Test executor type determination."""
        chain = ExploitChain(mock_llm, mock_emitter)

        assert chain._determine_executor_type("curl http://example.com").value == "http"
        assert chain._determine_executor_type("gcloud run deploy").value == "cloudrun"
        assert chain._determine_executor_type("ls -la").value == "shell"

    @pytest.mark.asyncio
    async def test_plan_exploit(
        self,
        mock_llm,
        mock_emitter,
        sample_vulnerability,
        sample_app_context,
        sample_knowledge_base,
    ):
        """Test exploit planning."""
        chain = ExploitChain(mock_llm, mock_emitter)
        plan = await chain.plan_exploit(
            sample_app_context,
            sample_vulnerability,
            sample_knowledge_base,
        )

        assert plan.vulnerability == sample_vulnerability
        assert len(plan.attack_vectors) > 0
        assert plan.initial_approach in plan.attack_vectors

    @pytest.mark.asyncio
    async def test_check_exploitation_success_sql_injection(
        self,
        mock_llm,
        mock_emitter,
        sample_vulnerability,
        sample_app_context,
    ):
        """Test exploitation success detection for SQL injection."""
        chain = ExploitChain(mock_llm, mock_emitter)

        step = ChainStep(
            step_number=1,
            chain_type=ChainType.EXPLOIT,
            reasoning="Test",
            command="curl http://example.com",
            expected_outcome="SQL error",
            success_criteria="Database error in response",
        )

        # Mock successful SQL injection
        from redteam_agent_core.chains.exploit import StepResult
        result = StepResult(
            success=True,
            output="ERROR: SQL syntax error near 'UNION SELECT'",
            exit_code=0,
        )

        success = await chain._check_exploitation_success(
            step, result, sample_vulnerability, sample_app_context
        )
        assert success is True

        # Mock failed attempt
        result.output = "Login failed"
        success = await chain._check_exploitation_success(
            step, result, sample_vulnerability, sample_app_context
        )
        assert success is False


class TestRemediationChain:
    """Tests for RemediationChain."""

    def test_init(self, mock_llm, mock_emitter):
        """Test chain initialization."""
        chain = RemediationChain(mock_llm, mock_emitter, max_attempts=5)
        assert chain.max_attempts == 5
        assert chain.result is None

    def test_determine_fix_approach(self, mock_llm, mock_emitter):
        """Test fix approach determination."""
        chain = RemediationChain(mock_llm, mock_emitter)

        assert "parameterized" in chain._determine_fix_approach("sql_injection").lower()
        assert "escape" in chain._determine_fix_approach("xss").lower()
        assert "whitelist" in chain._determine_fix_approach("ssrf").lower()

    def test_validate_python_syntax_valid(self, mock_llm, mock_emitter):
        """Test Python syntax validation with valid code."""
        chain = RemediationChain(mock_llm, mock_emitter)

        valid_code = """
def hello():
    print("Hello, World!")
"""
        errors = chain._validate_python_syntax(valid_code)
        assert len(errors) == 0

    def test_validate_python_syntax_invalid(self, mock_llm, mock_emitter):
        """Test Python syntax validation with invalid code."""
        chain = RemediationChain(mock_llm, mock_emitter)

        invalid_code = """
def hello(
    print("Hello, World!")
"""
        errors = chain._validate_python_syntax(invalid_code)
        assert len(errors) > 0
        assert "Syntax error" in errors[0]

    def test_generate_diff(self, mock_llm, mock_emitter):
        """Test diff generation."""
        chain = RemediationChain(mock_llm, mock_emitter)

        original = 'query = f"SELECT * FROM users WHERE id={id}"'
        fixed = 'query = "SELECT * FROM users WHERE id=%s"'

        diff = chain._generate_diff(original, fixed, "app/db.py")

        assert "---" in diff
        assert "+++" in diff
        assert "SELECT" in diff

    def test_find_code_location(self, mock_llm, mock_emitter):
        """Test finding code location in source."""
        chain = RemediationChain(mock_llm, mock_emitter)

        source = """
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}'"
    result = db.execute(query)
    return result
"""
        target = 'query = f"SELECT * FROM users'

        start, end = chain._find_code_location(source, target)
        assert start > 0
        assert end >= start

    @pytest.mark.asyncio
    async def test_apply_fix_success(self, mock_llm, mock_emitter):
        """Test successful fix application."""
        chain = RemediationChain(mock_llm, mock_emitter)

        codebase = {
            "app/auth.py": """
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}'"
    return db.execute(query)
"""
        }

        fix = CodeFix(
            file_path="app/auth.py",
            original_code='f"SELECT * FROM users WHERE username=\'{username}\'"',
            fixed_code='"SELECT * FROM users WHERE username=%s", (username,)',
            diff="...",
            explanation="Use parameterized query",
            line_start=3,
            line_end=3,
        )

        result = await chain.apply_fix(fix, codebase)

        assert result.success is True
        assert result.has_errors is False
        assert "app/auth.py" in result.files_modified

    @pytest.mark.asyncio
    async def test_apply_fix_file_not_found(self, mock_llm, mock_emitter):
        """Test fix application with missing file."""
        chain = RemediationChain(mock_llm, mock_emitter)

        codebase = {}

        fix = CodeFix(
            file_path="missing.py",
            original_code="old",
            fixed_code="new",
            diff="...",
            explanation="Fix",
            line_start=1,
            line_end=1,
        )

        result = await chain.apply_fix(fix, codebase)

        assert result.success is False
        assert result.has_errors is True
        assert "File not found" in result.errors[0]

    @pytest.mark.asyncio
    async def test_apply_fix_code_not_found(self, mock_llm, mock_emitter):
        """Test fix application when original code not found."""
        chain = RemediationChain(mock_llm, mock_emitter)

        codebase = {
            "app/auth.py": "def login(): pass"
        }

        fix = CodeFix(
            file_path="app/auth.py",
            original_code="nonexistent code",
            fixed_code="new code",
            diff="...",
            explanation="Fix",
            line_start=1,
            line_end=1,
        )

        result = await chain.apply_fix(fix, codebase)

        assert result.success is False
        assert result.has_errors is True
        assert "not found" in result.errors[0].lower()

    @pytest.mark.asyncio
    async def test_analyze_exploit(self, mock_llm, mock_emitter):
        """Test exploit analysis."""
        chain = RemediationChain(mock_llm, mock_emitter)

        exploit_result = ExploitResult(
            success=True,
            vulnerability_id="vuln-001",
            vulnerability_type="sql_injection",
            severity="high",
            steps_executed=[
                ChainStep(
                    step_number=1,
                    chain_type=ChainType.EXPLOIT,
                    reasoning="Test",
                    command="curl http://example.com/login?user=admin",
                    expected_outcome="SQL error",
                    success_criteria="Error in output",
                    output="app/auth.py error",
                )
            ],
            total_steps=1,
            summary="SQL injection successful",
        )

        codebase = {
            "app/auth.py": "def login(): pass",
            "app/api.py": "def api(): pass",
        }

        plan = await chain.analyze_exploit(exploit_result, codebase)

        assert plan.exploit_result == exploit_result
        assert "parameterized" in plan.fix_approach.lower()


class TestCodeFix:
    """Tests for CodeFix model."""

    def test_basic_fix(self):
        """Test basic CodeFix creation."""
        fix = CodeFix(
            file_path="app/db.py",
            original_code="query = f'{user}'",
            fixed_code="query = %s, (user,)",
            diff="- query = f'{user}'\n+ query = %s, (user,)",
            explanation="Use parameterized query",
            line_start=10,
            line_end=10,
        )

        assert fix.file_path == "app/db.py"
        assert fix.line_start == 10
