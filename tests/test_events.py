"""Tests for event emitter."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from redteam_agent_core.events import EventEmitter
from redteam_agent_core.models.events import (
    AgentEvent,
    CommandStatus,
    PipelineStage,
    ReasoningEvent,
    StageChangeEvent,
)
from redteam_agent_core.models.results import ChainType


class TestEventEmitter:
    """Tests for EventEmitter."""

    def test_init(self):
        """Test emitter initialization."""
        emitter = EventEmitter(
            session_id="session-1",
            run_id="run-1",
            buffer_size=100,
        )
        assert emitter.session_id == "session-1"
        assert emitter.run_id == "run-1"
        assert emitter.buffer_size == 100
        assert emitter.current_stage is None

    @pytest.mark.asyncio
    async def test_emit_event(self):
        """Test basic event emission."""
        emitter = EventEmitter(session_id="s1", run_id="r1")

        received_events = []

        async def callback(event):
            received_events.append(event)

        emitter.subscribe(callback)

        # Create and emit a simple event
        event = ReasoningEvent(
            session_id="s1",
            run_id="r1",
            step_number=1,
            chain_type="exploit",
            reasoning_text="Test reasoning",
        )
        await emitter.emit(event)

        assert len(received_events) == 1
        assert received_events[0].reasoning_text == "Test reasoning"

    @pytest.mark.asyncio
    async def test_buffer_events(self):
        """Test event buffering."""
        emitter = EventEmitter(session_id="s1", run_id="r1", buffer_size=5)

        # Emit more events than buffer size
        for i in range(10):
            event = ReasoningEvent(
                session_id="s1",
                run_id="r1",
                step_number=i,
                chain_type="exploit",
                reasoning_text=f"Step {i}",
            )
            await emitter.emit(event)

        # Only last 5 events should be in buffer
        buffered = emitter.get_buffered_events()
        assert len(buffered) == 5
        assert buffered[0].step_number == 5
        assert buffered[-1].step_number == 9

    @pytest.mark.asyncio
    async def test_subscribe_unsubscribe(self):
        """Test subscribe and unsubscribe."""
        emitter = EventEmitter(session_id="s1", run_id="r1")

        received = []

        async def callback(event):
            received.append(event)

        unsubscribe = emitter.subscribe(callback)

        # Emit event - should be received
        event1 = ReasoningEvent(
            session_id="s1",
            run_id="r1",
            step_number=1,
            chain_type="exploit",
            reasoning_text="First",
        )
        await emitter.emit(event1)
        assert len(received) == 1

        # Unsubscribe
        unsubscribe()

        # Emit another event - should not be received
        event2 = ReasoningEvent(
            session_id="s1",
            run_id="r1",
            step_number=2,
            chain_type="exploit",
            reasoning_text="Second",
        )
        await emitter.emit(event2)
        assert len(received) == 1  # Still 1

    @pytest.mark.asyncio
    async def test_set_stage(self):
        """Test stage change."""
        emitter = EventEmitter(session_id="s1", run_id="r1")

        received = []

        async def callback(event):
            received.append(event)

        emitter.subscribe(callback)

        # Set initial stage
        await emitter.set_stage(PipelineStage.SCANNING, "Starting scan")
        assert emitter.current_stage == PipelineStage.SCANNING
        assert len(received) == 1
        assert isinstance(received[0], StageChangeEvent)
        assert received[0].stage == PipelineStage.SCANNING
        assert received[0].previous_stage is None

        # Change stage
        await emitter.set_stage(PipelineStage.EXPLOITING, "Starting exploit")
        assert emitter.current_stage == PipelineStage.EXPLOITING
        assert len(received) == 2
        assert received[1].previous_stage == PipelineStage.SCANNING

    @pytest.mark.asyncio
    async def test_emit_reasoning(self):
        """Test reasoning event emission."""
        emitter = EventEmitter(session_id="s1", run_id="r1")

        received = []

        async def callback(event):
            received.append(event)

        emitter.subscribe(callback)

        await emitter.emit_reasoning(
            step_number=1,
            chain_type=ChainType.EXPLOIT,
            reasoning_text="Analyzing vulnerability...",
        )

        assert len(received) == 1
        event = received[0]
        assert isinstance(event, ReasoningEvent)
        assert event.step_number == 1
        assert event.chain_type == "exploit"
        assert event.reasoning_text == "Analyzing vulnerability..."

    @pytest.mark.asyncio
    async def test_emit_command(self):
        """Test command event emission."""
        emitter = EventEmitter(session_id="s1", run_id="r1")

        received = []

        async def callback(event):
            received.append(event)

        emitter.subscribe(callback)

        await emitter.emit_command(
            step_number=1,
            command="curl http://example.com",
            status=CommandStatus.RUNNING,
            executor_type="http",
        )

        assert len(received) == 1
        event = received[0]
        assert event.command == "curl http://example.com"
        assert event.status == CommandStatus.RUNNING

    @pytest.mark.asyncio
    async def test_emit_output(self):
        """Test output event emission."""
        emitter = EventEmitter(session_id="s1", run_id="r1")

        received = []

        async def callback(event):
            received.append(event)

        emitter.subscribe(callback)

        await emitter.emit_output(
            step_number=1,
            output="HTTP 200 OK",
            stream="stdout",
        )

        assert len(received) == 1
        assert received[0].output == "HTTP 200 OK"
        assert received[0].stream == "stdout"

    @pytest.mark.asyncio
    async def test_emit_exploit_result(self):
        """Test exploit result event emission."""
        emitter = EventEmitter(session_id="s1", run_id="r1")

        received = []

        async def callback(event):
            received.append(event)

        emitter.subscribe(callback)

        await emitter.emit_exploit_result(
            success=True,
            vulnerability_id="vuln-1",
            vulnerability_type="sql_injection",
            severity="high",
            summary="SQL injection successful",
            evidence="Retrieved database: users",
        )

        assert len(received) == 1
        event = received[0]
        assert event.success is True
        assert event.vulnerability_type == "sql_injection"
        assert event.evidence == "Retrieved database: users"

    @pytest.mark.asyncio
    async def test_emit_error(self):
        """Test error event emission."""
        emitter = EventEmitter(session_id="s1", run_id="r1")

        received = []

        async def callback(event):
            received.append(event)

        emitter.subscribe(callback)

        await emitter.emit_error(
            error_code="TIMEOUT",
            error_message="Command timed out",
            recoverable=True,
            step_number=5,
        )

        assert len(received) == 1
        event = received[0]
        assert event.error_code == "TIMEOUT"
        assert event.recoverable is True
        assert event.step_number == 5

    @pytest.mark.asyncio
    async def test_stream_events(self):
        """Test streaming events as async iterator."""
        emitter = EventEmitter(session_id="s1", run_id="r1")

        received = []

        async def producer():
            for i in range(3):
                await emitter.emit_reasoning(
                    step_number=i,
                    chain_type=ChainType.EXPLOIT,
                    reasoning_text=f"Step {i}",
                )
                await asyncio.sleep(0.01)
            await emitter.close()

        async def consumer():
            async for event in emitter.stream():
                received.append(event)

        # Run producer and consumer concurrently
        await asyncio.gather(producer(), consumer())

        assert len(received) == 3
        assert received[0].step_number == 0
        assert received[2].step_number == 2

    @pytest.mark.asyncio
    async def test_clear_buffer(self):
        """Test clearing the event buffer."""
        emitter = EventEmitter(session_id="s1", run_id="r1")

        await emitter.emit_reasoning(
            step_number=1,
            chain_type=ChainType.EXPLOIT,
            reasoning_text="Test",
        )

        assert len(emitter.get_buffered_events()) == 1

        emitter.clear_buffer()
        assert len(emitter.get_buffered_events()) == 0

    @pytest.mark.asyncio
    async def test_close_emitter(self):
        """Test closing the emitter."""
        emitter = EventEmitter(session_id="s1", run_id="r1")

        await emitter.close()

        # Emit after close should be ignored
        await emitter.emit_reasoning(
            step_number=1,
            chain_type=ChainType.EXPLOIT,
            reasoning_text="Ignored",
        )

        # Buffer should be empty since emit was ignored after close
        # Note: The buffer had 0 items before close
        assert len(emitter.get_buffered_events()) == 0

    @pytest.mark.asyncio
    async def test_subscriber_error_handling(self):
        """Test that subscriber errors don't break emission."""
        emitter = EventEmitter(session_id="s1", run_id="r1")

        successful_received = []

        async def failing_callback(event):
            raise Exception("Subscriber error")

        async def successful_callback(event):
            successful_received.append(event)

        emitter.subscribe(failing_callback)
        emitter.subscribe(successful_callback)

        # Event should still reach successful subscriber
        await emitter.emit_reasoning(
            step_number=1,
            chain_type=ChainType.EXPLOIT,
            reasoning_text="Test",
        )

        assert len(successful_received) == 1
