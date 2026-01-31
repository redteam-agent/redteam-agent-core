"""
Executor service client for running commands.

The executor service runs commands in an isolated environment against
target applications. This client communicates with the executor service
via HTTP.
"""

from datetime import datetime
from enum import Enum
from typing import AsyncIterator

import httpx
import structlog
from pydantic import BaseModel
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = structlog.get_logger(__name__)


class ExecutorType(str, Enum):
    """Type of executor to use."""

    HTTP = "http"
    SHELL = "shell"
    CLOUDRUN = "cloudrun"


class TargetInfo(BaseModel):
    """Information about the target application."""

    url: str
    gcp_project_id: str | None = None
    gcp_region: str | None = None
    gcp_service_name: str | None = None


class ExecuteRequest(BaseModel):
    """Request to execute a command."""

    session_id: str
    run_id: str
    command: str
    executor_type: ExecutorType
    target: TargetInfo
    timeout: int = 30


class ExecutionResult(BaseModel):
    """Result of command execution."""

    execution_id: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    truncated: bool = False


class OutputChunk(BaseModel):
    """A chunk of output from streaming execution."""

    stream: str  # "stdout" or "stderr"
    chunk: str
    timestamp: datetime


class ExecutorError(Exception):
    """Error from executor service."""

    def __init__(self, message: str, error_code: str | None = None, recoverable: bool = True):
        super().__init__(message)
        self.error_code = error_code
        self.recoverable = recoverable


class ExecutorClient:
    """
    HTTP client for the executor service.

    The executor service runs commands in isolated environments
    and returns the results.
    """

    def __init__(self, base_url: str, timeout: int = 30):
        """
        Initialize the executor client.

        Args:
            base_url: Base URL of the executor service
            timeout: Default timeout for command execution (seconds)
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=5),
    )
    async def execute(
        self,
        session_id: str,
        run_id: str,
        command: str,
        executor_type: ExecutorType,
        target: TargetInfo,
        timeout: int | None = None,
    ) -> ExecutionResult:
        """
        Execute a command on the executor service.

        Args:
            session_id: Current session ID
            run_id: Current run ID
            command: Command to execute
            executor_type: Type of executor (HTTP, SHELL, CLOUDRUN)
            target: Target application info
            timeout: Command timeout in seconds

        Returns:
            ExecutionResult with exit code and output

        Raises:
            ExecutorError: If execution fails
        """
        request = ExecuteRequest(
            session_id=session_id,
            run_id=run_id,
            command=command,
            executor_type=executor_type,
            target=target,
            timeout=timeout or self.timeout,
        )

        logger.debug(
            "executing_command",
            command=command[:100],
            executor_type=executor_type,
            target_url=target.url,
        )

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.base_url}/execute",
                    json=request.model_dump(),
                    timeout=float((timeout or self.timeout) + 5),  # Extra buffer
                )

                if response.status_code == 200:
                    data = response.json()
                    return ExecutionResult(**data)
                elif response.status_code == 400:
                    error = response.json()
                    raise ExecutorError(
                        message=error.get("message", "Bad request"),
                        error_code=error.get("error_code", "BAD_REQUEST"),
                        recoverable=False,
                    )
                elif response.status_code == 403:
                    error = response.json()
                    raise ExecutorError(
                        message=error.get("message", "Command blocked by security filter"),
                        error_code="COMMAND_BLOCKED",
                        recoverable=False,
                    )
                elif response.status_code == 408:
                    raise ExecutorError(
                        message="Command timed out",
                        error_code="TIMEOUT",
                        recoverable=True,
                    )
                else:
                    response.raise_for_status()

            except httpx.HTTPStatusError as e:
                logger.error("executor_http_error", status_code=e.response.status_code)
                raise ExecutorError(
                    message=f"HTTP error: {e.response.status_code}",
                    error_code="HTTP_ERROR",
                    recoverable=True,
                )
            except httpx.TimeoutException:
                logger.error("executor_timeout")
                raise ExecutorError(
                    message="Connection to executor timed out",
                    error_code="CONNECTION_TIMEOUT",
                    recoverable=True,
                )

        # Should not reach here, but satisfy type checker
        raise ExecutorError("Unexpected error", recoverable=False)

    async def stream_execute(
        self,
        session_id: str,
        run_id: str,
        command: str,
        executor_type: ExecutorType,
        target: TargetInfo,
        timeout: int | None = None,
    ) -> AsyncIterator[OutputChunk]:
        """
        Execute a command with streaming output.

        Uses Server-Sent Events (SSE) to stream output in real-time.

        Args:
            session_id: Current session ID
            run_id: Current run ID
            command: Command to execute
            executor_type: Type of executor
            target: Target application info
            timeout: Command timeout in seconds

        Yields:
            OutputChunk objects as output is received
        """
        request = ExecuteRequest(
            session_id=session_id,
            run_id=run_id,
            command=command,
            executor_type=executor_type,
            target=target,
            timeout=timeout or self.timeout,
        )

        logger.debug(
            "streaming_execute",
            command=command[:100],
            executor_type=executor_type,
        )

        async with httpx.AsyncClient() as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/execute/stream",
                json=request.model_dump(),
                timeout=float((timeout or self.timeout) + 5),
            ) as response:
                if response.status_code != 200:
                    content = await response.aread()
                    raise ExecutorError(
                        message=f"Stream error: {content.decode()}",
                        error_code="STREAM_ERROR",
                        recoverable=True,
                    )

                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        import json
                        data = json.loads(line[6:])
                        yield OutputChunk(
                            stream=data.get("stream", "stdout"),
                            chunk=data.get("chunk", ""),
                            timestamp=datetime.fromisoformat(
                                data.get("timestamp", datetime.utcnow().isoformat())
                            ),
                        )

    async def health_check(self) -> bool:
        """
        Check if the executor service is healthy.

        Returns:
            True if service is healthy, False otherwise
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/health",
                    timeout=5.0,
                )
                return response.status_code == 200
        except Exception:
            return False

    async def get_execution(self, execution_id: str) -> ExecutionResult | None:
        """
        Get the result of a previous execution.

        Args:
            execution_id: ID of the execution to retrieve

        Returns:
            ExecutionResult if found, None otherwise
        """
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.base_url}/executions/{execution_id}",
                    timeout=10.0,
                )
                if response.status_code == 200:
                    return ExecutionResult(**response.json())
                return None
            except Exception:
                return None
