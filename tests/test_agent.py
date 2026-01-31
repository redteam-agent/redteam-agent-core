"""Tests for RedTeamAgent."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from redteam_agent_core.agent import RedTeamAgent
from redteam_agent_core.config import Settings
from redteam_agent_core.models.app_context import AppContext, ArchitectureInfo, TechStackInfo


@pytest.fixture
def mock_settings():
    """Create mock settings for testing."""
    settings = MagicMock(spec=Settings)
    settings.OPENROUTER_API_KEY = "test-key"
    settings.OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
    settings.OPENROUTER_MODELS = ["z-ai/glm-4.7"]
    settings.APP_URL = "https://test.example.com"
    settings.APP_NAME = "test-app"
    settings.REDUCTO_API_KEY = "test-reducto-key"
    settings.REDUCTO_BASE_URL = "https://api.reducto.ai"
    settings.FIRECRAWL_API_KEY = "test-firecrawl-key"
    settings.FIRECRAWL_BASE_URL = "https://api.firecrawl.dev"
    settings.EXECUTOR_SERVICE_URL = "http://localhost:8001"
    settings.EXECUTOR_TIMEOUT = 30
    settings.MAX_EXPLOIT_STEPS = 30
    settings.MAX_REMEDIATION_ATTEMPTS = 5
    settings.CACHE_TTL_HOURS = 24
    settings.CACHE_DIR = ".cache"
    return settings


class TestRedTeamAgent:
    """Tests for RedTeamAgent."""

    def test_init(self, mock_settings):
        """Test agent initialization."""
        with patch("redteam_agent_core.agent.OpenRouterProvider"):
            with patch("redteam_agent_core.agent.ReductoProcessor"):
                with patch("redteam_agent_core.agent.FirecrawlClient"):
                    with patch("redteam_agent_core.agent.SecurityUseScanner"):
                        agent = RedTeamAgent(mock_settings)

                        assert agent.settings == mock_settings
                        assert agent.llm is not None
                        assert agent.document_processor is not None
                        assert agent.crawler is not None
                        assert agent.scanner is not None
                        assert agent.executor is not None

    def test_set_executor_url(self, mock_settings):
        """Test executor URL override."""
        with patch("redteam_agent_core.agent.OpenRouterProvider"):
            with patch("redteam_agent_core.agent.ReductoProcessor"):
                with patch("redteam_agent_core.agent.FirecrawlClient"):
                    with patch("redteam_agent_core.agent.SecurityUseScanner"):
                        agent = RedTeamAgent(mock_settings)

                        original_executor = agent.executor
                        agent.set_executor_url("http://new-executor:8002")

                        assert agent.executor is not original_executor
                        assert agent.executor.base_url == "http://new-executor:8002"

    @pytest.mark.asyncio
    async def test_build_context_without_documents(self, mock_settings):
        """Test building context without documents."""
        with patch("redteam_agent_core.agent.OpenRouterProvider"):
            with patch("redteam_agent_core.agent.ReductoProcessor"):
                with patch("redteam_agent_core.agent.FirecrawlClient"):
                    with patch("redteam_agent_core.agent.SecurityUseScanner"):
                        agent = RedTeamAgent(mock_settings)

                        context = await agent.build_context(
                            app_name="TestApp",
                            app_url="https://test.example.com",
                            app_description="A test application",
                            documents=[],
                            gcp_info={
                                "project_id": "test-project",
                                "region": "us-central1",
                                "service_name": "test-service",
                            },
                            github_info={
                                "org": "test-org",
                                "repo": "test-repo",
                            },
                            user_email="test@example.com",
                            session_id="session-1",
                        )

                        assert isinstance(context, AppContext)
                        assert context.app_name == "TestApp"
                        assert context.app_url == "https://test.example.com"
                        assert context.gcp_project_id == "test-project"
                        assert context.github_org == "test-org"
                        assert context.run_id is not None

    @pytest.mark.asyncio
    async def test_build_context_with_documents(self, mock_settings):
        """Test building context with documents."""
        mock_doc = MagicMock()
        mock_doc.tech_stack = TechStackInfo(languages=["python"])
        mock_doc.architecture = ArchitectureInfo()

        with patch("redteam_agent_core.agent.OpenRouterProvider"):
            with patch("redteam_agent_core.agent.ReductoProcessor") as mock_processor_class:
                mock_processor = MagicMock()
                mock_processor.process_document = AsyncMock(return_value=mock_doc)
                mock_processor.merge_results = MagicMock(
                    return_value=(
                        TechStackInfo(languages=["python"], frameworks=["fastapi"]),
                        ArchitectureInfo(),
                    )
                )
                mock_processor_class.return_value = mock_processor

                with patch("redteam_agent_core.agent.FirecrawlClient"):
                    with patch("redteam_agent_core.agent.SecurityUseScanner"):
                        agent = RedTeamAgent(mock_settings)

                        context = await agent.build_context(
                            app_name="TestApp",
                            app_url="https://test.example.com",
                            app_description="A test application",
                            documents=[(b"content", "architecture.pdf")],
                            gcp_info={},
                            github_info={},
                            user_email="test@example.com",
                            session_id="session-1",
                        )

                        assert "python" in context.tech_stack.languages
                        assert "fastapi" in context.tech_stack.frameworks


class TestAppContextGeneration:
    """Tests for app context generation."""

    @pytest.mark.asyncio
    async def test_context_has_run_id(self, mock_settings):
        """Test that context gets a unique run ID."""
        with patch("redteam_agent_core.agent.OpenRouterProvider"):
            with patch("redteam_agent_core.agent.ReductoProcessor"):
                with patch("redteam_agent_core.agent.FirecrawlClient"):
                    with patch("redteam_agent_core.agent.SecurityUseScanner"):
                        agent = RedTeamAgent(mock_settings)

                        ctx1 = await agent.build_context(
                            app_name="App1",
                            app_url="https://app1.com",
                            app_description="App 1",
                            documents=[],
                            gcp_info={},
                            github_info={},
                            user_email="user@test.com",
                            session_id="session-1",
                        )

                        ctx2 = await agent.build_context(
                            app_name="App2",
                            app_url="https://app2.com",
                            app_description="App 2",
                            documents=[],
                            gcp_info={},
                            github_info={},
                            user_email="user@test.com",
                            session_id="session-2",
                        )

                        assert ctx1.run_id != ctx2.run_id

    @pytest.mark.asyncio
    async def test_context_uses_gcp_defaults(self, mock_settings):
        """Test that context handles missing GCP info."""
        with patch("redteam_agent_core.agent.OpenRouterProvider"):
            with patch("redteam_agent_core.agent.ReductoProcessor"):
                with patch("redteam_agent_core.agent.FirecrawlClient"):
                    with patch("redteam_agent_core.agent.SecurityUseScanner"):
                        agent = RedTeamAgent(mock_settings)

                        context = await agent.build_context(
                            app_name="TestApp",
                            app_url="https://test.example.com",
                            app_description="Test",
                            documents=[],
                            gcp_info={},  # Empty GCP info
                            github_info={},
                            user_email="test@test.com",
                            session_id="s1",
                        )

                        assert context.gcp_project_id == ""
                        assert context.gcp_region == ""
                        assert context.gcp_service_name == ""
                        # Container URL should default to app URL
                        assert context.gcp_container_url == "https://test.example.com"


class TestDocumentTypeDetection:
    """Tests for document type detection."""

    @pytest.mark.asyncio
    async def test_architecture_document_detection(self, mock_settings):
        """Test detection of architecture documents."""
        mock_doc = MagicMock()
        mock_doc.tech_stack = TechStackInfo()
        mock_doc.architecture = ArchitectureInfo()

        with patch("redteam_agent_core.agent.OpenRouterProvider"):
            with patch("redteam_agent_core.agent.ReductoProcessor") as mock_processor_class:
                mock_processor = MagicMock()
                mock_processor.process_document = AsyncMock(return_value=mock_doc)
                mock_processor.merge_results = MagicMock(
                    return_value=(TechStackInfo(), ArchitectureInfo())
                )
                mock_processor_class.return_value = mock_processor

                with patch("redteam_agent_core.agent.FirecrawlClient"):
                    with patch("redteam_agent_core.agent.SecurityUseScanner"):
                        agent = RedTeamAgent(mock_settings)

                        await agent.build_context(
                            app_name="Test",
                            app_url="https://test.com",
                            app_description="Test",
                            documents=[(b"content", "system_architecture_diagram.pdf")],
                            gcp_info={},
                            github_info={},
                            user_email="test@test.com",
                            session_id="s1",
                        )

                        # Check that process_document was called with architecture type
                        call_args = mock_processor.process_document.call_args
                        from redteam_agent_core.document import DocType
                        assert call_args[1]["doc_type"] == DocType.ARCHITECTURE_DIAGRAM

    @pytest.mark.asyncio
    async def test_api_document_detection(self, mock_settings):
        """Test detection of API documents."""
        mock_doc = MagicMock()
        mock_doc.tech_stack = TechStackInfo()
        mock_doc.architecture = ArchitectureInfo()

        with patch("redteam_agent_core.agent.OpenRouterProvider"):
            with patch("redteam_agent_core.agent.ReductoProcessor") as mock_processor_class:
                mock_processor = MagicMock()
                mock_processor.process_document = AsyncMock(return_value=mock_doc)
                mock_processor.merge_results = MagicMock(
                    return_value=(TechStackInfo(), ArchitectureInfo())
                )
                mock_processor_class.return_value = mock_processor

                with patch("redteam_agent_core.agent.FirecrawlClient"):
                    with patch("redteam_agent_core.agent.SecurityUseScanner"):
                        agent = RedTeamAgent(mock_settings)

                        await agent.build_context(
                            app_name="Test",
                            app_url="https://test.com",
                            app_description="Test",
                            documents=[(b"content", "api_endpoints.md")],
                            gcp_info={},
                            github_info={},
                            user_email="test@test.com",
                            session_id="s1",
                        )

                        call_args = mock_processor.process_document.call_args
                        from redteam_agent_core.document import DocType
                        assert call_args[1]["doc_type"] == DocType.API_DOC
