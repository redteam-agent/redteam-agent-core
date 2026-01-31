"""Tests for document processor."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from redteam_agent_core.config import Settings
from redteam_agent_core.document import DocType, ProcessedDocument, ReductoProcessor
from redteam_agent_core.models.app_context import TechStackInfo, ArchitectureInfo


@pytest.fixture
def mock_settings():
    """Create mock settings for testing."""
    settings = MagicMock(spec=Settings)
    settings.REDUCTO_API_KEY = "test-api-key"
    settings.REDUCTO_BASE_URL = "https://api.reducto.ai"
    return settings


class TestReductoProcessor:
    """Tests for ReductoProcessor."""

    def test_init(self, mock_settings):
        """Test processor initialization."""
        processor = ReductoProcessor(mock_settings)
        assert processor.api_key == "test-api-key"
        assert processor.base_url == "https://api.reducto.ai"

    def test_get_content_type(self, mock_settings):
        """Test content type detection."""
        processor = ReductoProcessor(mock_settings)

        assert processor._get_content_type("doc.pdf") == "application/pdf"
        assert processor._get_content_type("image.png") == "image/png"
        assert processor._get_content_type("image.jpg") == "image/jpeg"
        assert processor._get_content_type("readme.md") == "text/markdown"
        assert processor._get_content_type("file.unknown") == "application/octet-stream"

    def test_find_matches(self, mock_settings):
        """Test pattern matching in text."""
        processor = ReductoProcessor(mock_settings)

        text = "we use python and django with postgresql database"
        patterns = ["python", "java", "django", "flask", "postgresql", "mysql"]

        matches = processor._find_matches(text, patterns)
        assert "python" in matches
        assert "django" in matches
        assert "postgresql" in matches
        assert "java" not in matches
        assert "flask" not in matches

    def test_extract_tech_stack(self, mock_settings):
        """Test technology stack extraction."""
        processor = ReductoProcessor(mock_settings)

        text = """
        Our application is built with Python and FastAPI.
        We use PostgreSQL for the database and Redis for caching.
        Authentication is handled via JWT tokens.
        Deployed on GCP Cloud Run.
        """

        tech_stack = processor._extract_tech_stack(text, {})

        assert "python" in tech_stack.languages
        assert "fastapi" in tech_stack.frameworks
        assert "postgresql" in tech_stack.databases
        assert "redis" in tech_stack.databases
        assert "jwt" in tech_stack.authentication
        assert "cloud run" in tech_stack.cloud_services

    def test_extract_architecture_from_text(self, mock_settings):
        """Test architecture extraction from text patterns."""
        processor = ReductoProcessor(mock_settings)

        text = """
        The system has an API gateway that routes to the backend.
        Frontend is a React application.
        We use a cache layer with Redis.
        JWT authentication is used for security.
        """

        architecture = processor._extract_architecture(text, {})

        component_types = [c.type for c in architecture.components]
        assert "api" in component_types
        assert "backend" in component_types
        assert "frontend" in component_types
        assert "cache" in component_types
        assert architecture.authentication_type == "jwt"

    def test_extract_architecture_from_structured_data(self, mock_settings):
        """Test architecture extraction from structured extracted data."""
        processor = ReductoProcessor(mock_settings)

        extracted_data = {
            "components": [
                {"name": "API Service", "type": "api", "description": "Main API"},
                {"name": "Database", "type": "database", "technology": "PostgreSQL"},
            ],
            "entry_points": [
                {"url": "/api/users", "method": "GET", "auth_required": True},
                {"url": "/api/login", "method": "POST", "auth_required": False},
            ],
        }

        architecture = processor._extract_architecture("", extracted_data)

        assert len(architecture.components) == 2
        assert architecture.components[0].name == "API Service"
        assert architecture.components[1].technology == "PostgreSQL"

        assert len(architecture.entry_points) == 2
        assert architecture.entry_points[0].url == "/api/users"
        assert architecture.entry_points[0].authentication_required is True

    def test_extract_api_info(self, mock_settings):
        """Test API endpoint extraction from documentation."""
        processor = ReductoProcessor(mock_settings)

        text = """
        API Documentation:
        GET /api/users - List all users
        POST /api/users - Create a user
        DELETE /api/users/{id} - Delete a user
        """

        architecture = processor._extract_api_info(text, {})

        assert len(architecture.entry_points) >= 3
        methods = [ep.method for ep in architecture.entry_points]
        assert "GET" in methods
        assert "POST" in methods
        assert "DELETE" in methods

    @pytest.mark.asyncio
    async def test_process_document(self, mock_settings):
        """Test document processing."""
        mock_response = {
            "text": "Application uses Python and FastAPI with PostgreSQL",
            "extracted": {},
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_response_obj = MagicMock()
            mock_response_obj.json.return_value = mock_response
            mock_response_obj.raise_for_status = MagicMock()
            mock_client.post = AsyncMock(return_value=mock_response_obj)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            processor = ReductoProcessor(mock_settings)
            result = await processor.process_document(
                file_content=b"test content",
                filename="architecture.pdf",
                doc_type=DocType.ARCHITECTURE_DIAGRAM,
            )

            assert isinstance(result, ProcessedDocument)
            assert result.filename == "architecture.pdf"
            assert result.doc_type == DocType.ARCHITECTURE_DIAGRAM
            assert result.tech_stack is not None
            assert "python" in result.tech_stack.languages

    def test_merge_results(self, mock_settings):
        """Test merging multiple document results."""
        processor = ReductoProcessor(mock_settings)

        doc1 = ProcessedDocument(
            filename="doc1.pdf",
            doc_type=DocType.TECH_SPEC,
            raw_text="",
            extracted_data={},
            tech_stack=TechStackInfo(
                languages=["python"],
                frameworks=["fastapi"],
                databases=["postgresql"],
            ),
            architecture=ArchitectureInfo(authentication_type="jwt"),
        )

        doc2 = ProcessedDocument(
            filename="doc2.pdf",
            doc_type=DocType.ARCHITECTURE_DIAGRAM,
            raw_text="",
            extracted_data={},
            tech_stack=TechStackInfo(
                languages=["javascript"],
                frameworks=["react"],
                databases=["redis"],
            ),
            architecture=None,
        )

        merged_tech, merged_arch = processor.merge_results([doc1, doc2])

        assert "python" in merged_tech.languages
        assert "javascript" in merged_tech.languages
        assert "fastapi" in merged_tech.frameworks
        assert "react" in merged_tech.frameworks
        assert "postgresql" in merged_tech.databases
        assert "redis" in merged_tech.databases
        assert merged_arch.authentication_type == "jwt"


class TestProcessedDocument:
    """Tests for ProcessedDocument model."""

    def test_basic_document(self):
        """Test basic document creation."""
        doc = ProcessedDocument(
            filename="test.pdf",
            doc_type=DocType.GENERAL,
            raw_text="Sample text",
            extracted_data={"key": "value"},
        )

        assert doc.filename == "test.pdf"
        assert doc.doc_type == DocType.GENERAL
        assert doc.raw_text == "Sample text"
        assert doc.tech_stack is None
        assert doc.architecture is None

    def test_document_with_tech_stack(self):
        """Test document with tech stack."""
        doc = ProcessedDocument(
            filename="test.pdf",
            doc_type=DocType.TECH_SPEC,
            raw_text="",
            extracted_data={},
            tech_stack=TechStackInfo(languages=["python"]),
        )

        assert doc.tech_stack is not None
        assert "python" in doc.tech_stack.languages
