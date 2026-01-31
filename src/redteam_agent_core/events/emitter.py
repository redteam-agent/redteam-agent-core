"""
Event emitter for streaming events to the API layer.

Events are streamed to the frontend via WebSocket:
- Left Panel: Reasoning events (GLM-4.7 thinking)
- Right Panel: Command and output events (terminal display)
- Progress: Stage change events
"""

import asyncio
from collections import deque
from typing import AsyncIterator, Awaitable, Callable
from uuid import uuid4

import structlog

from ..models.events import (
    AgentEvent,
    CommandEvent,
    CommandStatus,
    ErrorEvent,
    ExploitResultEvent,
    OutputEvent,
    PipelineStage,
    ReasoningEvent,
    RemediationResultEvent,
    StageChangeEvent,
)
from ..models.results import ChainType

logger = structlog.get_logger(__name__)


class EventEmitter:
    """
    Event emitter for streaming events to clients.

    Provides methods for emitting different event types and
    supports both callback-based and async iterator consumption.
    """

    def __init__(
        self,
        session_id: str,
        run_id: str,
        buffer_size: int = 1000,
    ):
        """
        Initialize the event emitter.

        Args:
            session_id: Current session ID
            run_id: Current run ID
            buffer_size: Maximum events to buffer for replay
        """
        self.session_id = session_id
        self.run_id = run_id
        self.buffer_size = buffer_size

        self._buffer: deque[AgentEvent] = deque(maxlen=buffer_size)
        self._subscribers: list[Callable[[AgentEvent], Awaitable[None]]] = []
        self._current_stage: PipelineStage | None = None
        self._event_queue: asyncio.Queue[AgentEvent | None] = asyncio.Queue()
        self._closed = False

    @property
    def current_stage(self) -> PipelineStage | None:
        """Get the current pipeline stage."""
        return self._current_stage

    async def emit(self, event: AgentEvent) -> None:
        """
        Emit an event to all subscribers.

        Args:
            event: The event to emit
        """
        if self._closed:
            logger.warning("emit_after_close", event_type=event.event_type)
            return

        # Add to buffer for replay
        self._buffer.append(event)

        # Notify all subscribers
        for subscriber in self._subscribers:
            try:
                await subscriber(event)
            except Exception as e:
                logger.error(
                    "subscriber_error",
                    event_type=event.event_type,
                    error=str(e),
                )

        # Add to queue for stream() consumers
        await self._event_queue.put(event)

        logger.debug(
            "event_emitted",
            event_type=event.event_type,
            event_id=event.event_id,
        )

    def subscribe(
        self,
        callback: Callable[[AgentEvent], Awaitable[None]],
    ) -> Callable[[], None]:
        """
        Subscribe to events.

        Args:
            callback: Async function to call for each event

        Returns:
            Unsubscribe function
        """
        self._subscribers.append(callback)

        def unsubscribe():
            if callback in self._subscribers:
                self._subscribers.remove(callback)

        return unsubscribe

    async def stream(self) -> AsyncIterator[AgentEvent]:
        """
        Stream events as an async iterator.

        Yields:
            Events as they are emitted
        """
        while not self._closed:
            try:
                event = await asyncio.wait_for(
                    self._event_queue.get(),
                    timeout=1.0,
                )
                if event is None:
                    break
                yield event
            except asyncio.TimeoutError:
                continue

    def get_buffered_events(self) -> list[AgentEvent]:
        """
        Get all buffered events for replay on reconnection.

        Returns:
            List of buffered events
        """
        return list(self._buffer)

    def clear_buffer(self) -> None:
        """Clear the event buffer."""
        self._buffer.clear()

    async def close(self) -> None:
        """Close the emitter and signal stream end."""
        self._closed = True
        await self._event_queue.put(None)  # Signal end of stream

    # Convenience methods for common event types

    async def set_stage(
        self,
        stage: PipelineStage,
        message: str,
    ) -> None:
        """
        Set the current pipeline stage and emit stage change event.

        Args:
            stage: New pipeline stage
            message: Human-readable status message
        """
        previous_stage = self._current_stage
        self._current_stage = stage

        event = StageChangeEvent(
            session_id=self.session_id,
            run_id=self.run_id,
            stage=stage,
            previous_stage=previous_stage,
            message=message,
        )
        await self.emit(event)

        logger.info(
            "stage_change",
            from_stage=previous_stage,
            to_stage=stage,
            message=message,
        )

    async def emit_reasoning(
        self,
        step_number: int,
        chain_type: ChainType,
        reasoning_text: str,
    ) -> None:
        """
        Emit a reasoning event (for left panel display).

        Args:
            step_number: Current step number
            chain_type: Type of chain (exploit or remediation)
            reasoning_text: The reasoning/thinking text
        """
        event = ReasoningEvent(
            session_id=self.session_id,
            run_id=self.run_id,
            step_number=step_number,
            chain_type=chain_type.value,
            reasoning_text=reasoning_text,
        )
        await self.emit(event)

    async def emit_command(
        self,
        step_number: int,
        command: str,
        status: CommandStatus,
        executor_type: str,
    ) -> None:
        """
        Emit a command event (for right panel display).

        Args:
            step_number: Current step number
            command: The command being executed
            status: Command execution status
            executor_type: Type of executor (http, shell, cloudrun)
        """
        event = CommandEvent(
            session_id=self.session_id,
            run_id=self.run_id,
            step_number=step_number,
            command=command,
            status=status,
            executor_type=executor_type,
        )
        await self.emit(event)

    async def emit_output(
        self,
        step_number: int,
        output: str,
        stream: str = "stdout",
        is_truncated: bool = False,
    ) -> None:
        """
        Emit an output event (for right panel display).

        Args:
            step_number: Current step number
            output: The command output
            stream: Output stream (stdout or stderr)
            is_truncated: Whether output was truncated
        """
        event = OutputEvent(
            session_id=self.session_id,
            run_id=self.run_id,
            step_number=step_number,
            output=output,
            stream=stream,
            is_truncated=is_truncated,
        )
        await self.emit(event)

    async def emit_exploit_result(
        self,
        success: bool,
        vulnerability_id: str,
        vulnerability_type: str,
        severity: str,
        summary: str,
        evidence: str | None = None,
    ) -> None:
        """
        Emit an exploit result event.

        Args:
            success: Whether exploit was successful
            vulnerability_id: ID of the vulnerability
            vulnerability_type: Type of vulnerability
            severity: Vulnerability severity
            summary: Summary of the exploit attempt
            evidence: Proof of exploitation if successful
        """
        event = ExploitResultEvent(
            session_id=self.session_id,
            run_id=self.run_id,
            success=success,
            vulnerability_id=vulnerability_id,
            vulnerability_type=vulnerability_type,
            severity=severity,
            summary=summary,
            evidence=evidence,
        )
        await self.emit(event)

    async def emit_remediation_result(
        self,
        success: bool,
        files_changed: list[str],
        fix_summary: str,
        verification_passed: bool,
        pr_url: str | None = None,
    ) -> None:
        """
        Emit a remediation result event.

        Args:
            success: Whether remediation was successful
            files_changed: List of modified files
            fix_summary: Summary of the fix
            verification_passed: Whether fix verification passed
            pr_url: URL of created PR if applicable
        """
        event = RemediationResultEvent(
            session_id=self.session_id,
            run_id=self.run_id,
            success=success,
            files_changed=files_changed,
            fix_summary=fix_summary,
            verification_passed=verification_passed,
            pr_url=pr_url,
        )
        await self.emit(event)

    async def emit_error(
        self,
        error_code: str,
        error_message: str,
        recoverable: bool = True,
        step_number: int | None = None,
    ) -> None:
        """
        Emit an error event.

        Args:
            error_code: Error code for categorization
            error_message: Human-readable error message
            recoverable: Whether the error is recoverable
            step_number: Step number where error occurred (if applicable)
        """
        event = ErrorEvent(
            session_id=self.session_id,
            run_id=self.run_id,
            error_code=error_code,
            error_message=error_message,
            recoverable=recoverable,
            step_number=step_number,
        )
        await self.emit(event)

        if not recoverable:
            logger.error(
                "non_recoverable_error",
                error_code=error_code,
                message=error_message,
            )
