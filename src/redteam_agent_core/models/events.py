"""
Event models for streaming to the API layer.

These events are emitted by the core library and streamed to the frontend
via WebSocket by the API service. The frontend uses these to update:
- Left panel: Reasoning events
- Right panel: Command and output events
- Status bar: Stage change events
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class PipelineStage(str, Enum):
    """Stages in the security testing pipeline."""

    PROCESSING_DOCUMENTS = "processing_documents"
    CRAWLING_VULNERABILITIES = "crawling_vulnerabilities"
    SCANNING = "scanning"
    EXPLOITING = "exploiting"
    REMEDIATING = "remediating"
    CREATING_PR = "creating_pr"
    SENDING_EMAIL = "sending_email"
    COMPLETED = "completed"
    FAILED = "failed"


class CommandStatus(str, Enum):
    """Status of a command execution."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


class AgentEvent(BaseModel):
    """Base class for all agent events."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: str
    session_id: str
    run_id: str


class ReasoningEvent(AgentEvent):
    """
    Emitted when the LLM generates reasoning.

    For GLM-4.7, this is extracted from <think> tags.
    Displayed in the left panel of the frontend.
    """

    event_type: Literal["reasoning"] = "reasoning"
    step_number: int
    chain_type: Literal["exploit", "remediation"]
    reasoning_text: str


class CommandEvent(AgentEvent):
    """
    Emitted when a command is about to be executed or has completed.

    Displayed in the right panel (terminal) of the frontend.
    """

    event_type: Literal["command"] = "command"
    step_number: int
    command: str
    status: CommandStatus
    executor_type: Literal["http", "shell", "cloudrun"]


class OutputEvent(AgentEvent):
    """
    Emitted when command output is received.

    Displayed in the right panel (terminal) of the frontend.
    """

    event_type: Literal["output"] = "output"
    step_number: int
    output: str
    stream: Literal["stdout", "stderr"]
    is_truncated: bool = False


class StageChangeEvent(AgentEvent):
    """
    Emitted when the pipeline moves to a new stage.

    Used to update the progress indicator in the frontend.
    """

    event_type: Literal["stage_change"] = "stage_change"
    stage: PipelineStage
    previous_stage: PipelineStage | None
    message: str


class ExploitResultEvent(AgentEvent):
    """
    Emitted when an exploit attempt completes.

    Contains summary information about the exploit result.
    """

    event_type: Literal["exploit_result"] = "exploit_result"
    success: bool
    vulnerability_id: str
    vulnerability_type: str
    severity: str
    summary: str
    evidence: str | None = None


class RemediationResultEvent(AgentEvent):
    """
    Emitted when remediation completes.

    Contains information about the fix and verification status.
    """

    event_type: Literal["remediation_result"] = "remediation_result"
    success: bool
    files_changed: list[str]
    fix_summary: str
    verification_passed: bool
    pr_url: str | None = None


class ErrorEvent(AgentEvent):
    """
    Emitted when an error occurs.

    Used to notify the frontend of errors without stopping the pipeline
    (for recoverable errors) or to signal pipeline failure.
    """

    event_type: Literal["error"] = "error"
    error_code: str
    error_message: str
    recoverable: bool
    step_number: int | None = None


# Union type for all events (useful for type checking)
AnyEvent = (
    ReasoningEvent
    | CommandEvent
    | OutputEvent
    | StageChangeEvent
    | ExploitResultEvent
    | RemediationResultEvent
    | ErrorEvent
)
