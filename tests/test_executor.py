"""Tests for executor client."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from redteam_agent_core.executor import (
    ExecutionResult,
    ExecutorClient,
    ExecutorError,
    ExecutorType,
    OutputChunk,
    TargetInfo,
)


@pytest.fixture
def target_info():
    """Create a sample target info."""
    return TargetInfo(
        url="https://app.example.com",
        gcp_project_id="test-project",
        gcp_region="us-central1",
        gcp_service_name="test-service",
    )


class TestExecutorClient:
    """Tests for ExecutorClient."""

    def test_init(self):
        """Test client initialization."""
        client = ExecutorClient("http://localhost:8001")
        assert client.base_url == "http://localhost:8001"
        assert client.timeout == 30

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is stripped from base URL."""
        client = ExecutorClient("http://localhost:8001/")
        assert client.base_url == "http://localhost:8001"

    @pytest.mark.asyncio
    async def test_execute_success(self, target_info):
        """Test successful command execution."""
        mock_response = {
            "execution_id": "exec-123",
            "exit_code": 0,
            "stdout": "Success output",
            "stderr": "",
            "duration_ms": 100,
            "truncated": False,
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_response_obj = MagicMock()
            mock_response_obj.status_code = 200
            mock_response_obj.json.return_value = mock_response

            mock_client = MagicMock()
            mock_client.post = AsyncMock(return_value=mock_response_obj)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            client = ExecutorClient("http://localhost:8001")
            result = await client.execute(
                session_id="session-1",
                run_id="run-1",
                command="curl http://example.com",
                executor_type=ExecutorType.HTTP,
                target=target_info,
            )

            assert isinstance(result, ExecutionResult)
            assert result.execution_id == "exec-123"
            assert result.exit_code == 0
            assert result.stdout == "Success output"

    @pytest.mark.asyncio
    async def test_execute_command_blocked(self, target_info):
        """Test command blocked by security filter."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.json.return_value = {
            "message": "Command blocked: rm -rf",
            "error_code": "COMMAND_BLOCKED",
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            client = ExecutorClient("http://localhost:8001")

            with pytest.raises(ExecutorError) as exc_info:
                await client.execute(
                    session_id="session-1",
                    run_id="run-1",
                    command="rm -rf /",
                    executor_type=ExecutorType.SHELL,
                    target=target_info,
                )

            assert exc_info.value.error_code == "COMMAND_BLOCKED"
            assert exc_info.value.recoverable is False

    @pytest.mark.asyncio
    async def test_execute_timeout(self, target_info):
        """Test command timeout."""
        mock_response = MagicMock()
        mock_response.status_code = 408
        mock_response.json.return_value = {"message": "Timeout"}

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            client = ExecutorClient("http://localhost:8001")

            with pytest.raises(ExecutorError) as exc_info:
                await client.execute(
                    session_id="session-1",
                    run_id="run-1",
                    command="sleep 1000",
                    executor_type=ExecutorType.SHELL,
                    target=target_info,
                )

            assert exc_info.value.error_code == "TIMEOUT"
            assert exc_info.value.recoverable is True

    @pytest.mark.asyncio
    async def test_execute_bad_request(self, target_info):
        """Test bad request error."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "message": "Invalid command",
            "error_code": "INVALID_COMMAND",
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            client = ExecutorClient("http://localhost:8001")

            with pytest.raises(ExecutorError) as exc_info:
                await client.execute(
                    session_id="session-1",
                    run_id="run-1",
                    command="",
                    executor_type=ExecutorType.SHELL,
                    target=target_info,
                )

            assert exc_info.value.recoverable is False

    @pytest.mark.asyncio
    async def test_health_check_success(self):
        """Test successful health check."""
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            client = ExecutorClient("http://localhost:8001")
            result = await client.health_check()

            assert result is True

    @pytest.mark.asyncio
    async def test_health_check_failure(self):
        """Test failed health check."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            client = ExecutorClient("http://localhost:8001")
            result = await client.health_check()

            assert result is False

    @pytest.mark.asyncio
    async def test_get_execution_found(self):
        """Test retrieving existing execution."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "execution_id": "exec-123",
            "exit_code": 0,
            "stdout": "Output",
            "stderr": "",
            "duration_ms": 100,
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            client = ExecutorClient("http://localhost:8001")
            result = await client.get_execution("exec-123")

            assert result is not None
            assert result.execution_id == "exec-123"

    @pytest.mark.asyncio
    async def test_get_execution_not_found(self):
        """Test retrieving non-existent execution."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            client = ExecutorClient("http://localhost:8001")
            result = await client.get_execution("nonexistent")

            assert result is None


class TestTargetInfo:
    """Tests for TargetInfo model."""

    def test_basic_target(self):
        """Test basic target info."""
        target = TargetInfo(url="https://example.com")
        assert target.url == "https://example.com"
        assert target.gcp_project_id is None

    def test_full_target(self):
        """Test target with all fields."""
        target = TargetInfo(
            url="https://app.run.app",
            gcp_project_id="my-project",
            gcp_region="us-central1",
            gcp_service_name="my-service",
        )
        assert target.gcp_project_id == "my-project"
        assert target.gcp_region == "us-central1"


class TestExecutionResult:
    """Tests for ExecutionResult model."""

    def test_successful_result(self):
        """Test successful execution result."""
        result = ExecutionResult(
            execution_id="exec-1",
            exit_code=0,
            stdout="Hello, World!",
            stderr="",
            duration_ms=50,
        )
        assert result.exit_code == 0
        assert result.truncated is False

    def test_failed_result(self):
        """Test failed execution result."""
        result = ExecutionResult(
            execution_id="exec-2",
            exit_code=1,
            stdout="",
            stderr="Error: file not found",
            duration_ms=100,
            truncated=False,
        )
        assert result.exit_code == 1
        assert "Error" in result.stderr


class TestExecutorError:
    """Tests for ExecutorError."""

    def test_recoverable_error(self):
        """Test recoverable error."""
        error = ExecutorError("Timeout", error_code="TIMEOUT", recoverable=True)
        assert str(error) == "Timeout"
        assert error.error_code == "TIMEOUT"
        assert error.recoverable is True

    def test_non_recoverable_error(self):
        """Test non-recoverable error."""
        error = ExecutorError("Blocked", error_code="BLOCKED", recoverable=False)
        assert error.recoverable is False
