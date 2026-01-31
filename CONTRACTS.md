# Integration Contracts

This document defines the interfaces and data contracts that `redteam-agent-core` exposes to other services. Engineers working on other repositories MUST use these contracts for integration.

## Table of Contents
1. [Event Contracts](#event-contracts)
2. [Executor Client Contract](#executor-client-contract)
3. [Data Models](#data-models)
4. [Error Handling](#error-handling)

---

## Event Contracts

The core library emits events that the API layer streams to the frontend via WebSocket.

### Event Base Schema

```python
class AgentEvent(BaseModel):
    event_id: str                    # UUID
    timestamp: datetime              # ISO 8601
    event_type: str                  # Discriminator field
    session_id: str                  # Links to user session
    run_id: str                      # Links to agent run
```

### Event Types

#### 1. ReasoningEvent
Emitted when the LLM generates reasoning (from `<think>` tags in GLM-4.7).

```json
{
    "event_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z",
    "event_type": "reasoning",
    "session_id": "session-uuid",
    "run_id": "run-uuid",
    "step_number": 1,
    "chain_type": "exploit",
    "reasoning_text": "Based on the SQL injection vulnerability in the login endpoint..."
}
```

#### 2. CommandEvent
Emitted when a command is about to be executed or has finished.

```json
{
    "event_id": "uuid",
    "timestamp": "2024-01-15T10:30:01Z",
    "event_type": "command",
    "session_id": "session-uuid",
    "run_id": "run-uuid",
    "step_number": 1,
    "command": "curl -X POST https://app.example.com/login -d \"user=admin' OR '1'='1\"",
    "status": "running",
    "executor_type": "http"
}
```

Status values: `pending`, `running`, `success`, `failed`, `timeout`

#### 3. OutputEvent
Emitted when command output is received.

```json
{
    "event_id": "uuid",
    "timestamp": "2024-01-15T10:30:02Z",
    "event_type": "output",
    "session_id": "session-uuid",
    "run_id": "run-uuid",
    "step_number": 1,
    "output": "HTTP/1.1 200 OK\n{\"status\": \"success\"}",
    "stream": "stdout",
    "is_truncated": false
}
```

#### 4. StageChangeEvent
Emitted when the pipeline moves to a new stage.

```json
{
    "event_id": "uuid",
    "timestamp": "2024-01-15T10:30:00Z",
    "event_type": "stage_change",
    "session_id": "session-uuid",
    "run_id": "run-uuid",
    "stage": "exploiting",
    "previous_stage": "scanning",
    "message": "Starting exploit chain execution"
}
```

Stage values: `processing_documents`, `crawling_vulnerabilities`, `scanning`, `exploiting`, `remediating`, `creating_pr`, `completed`, `failed`

#### 5. ExploitResultEvent
Emitted when an exploit attempt completes.

```json
{
    "event_id": "uuid",
    "timestamp": "2024-01-15T10:35:00Z",
    "event_type": "exploit_result",
    "session_id": "session-uuid",
    "run_id": "run-uuid",
    "success": true,
    "vulnerability_id": "vuln-001",
    "vulnerability_type": "sql_injection",
    "severity": "critical",
    "summary": "Successfully exploited SQL injection in /api/login endpoint",
    "evidence": "Retrieved admin credentials from database"
}
```

#### 6. RemediationResultEvent
Emitted when remediation completes.

```json
{
    "event_id": "uuid",
    "timestamp": "2024-01-15T10:40:00Z",
    "event_type": "remediation_result",
    "session_id": "session-uuid",
    "run_id": "run-uuid",
    "success": true,
    "files_changed": ["src/api/auth.py"],
    "fix_summary": "Added parameterized queries to prevent SQL injection",
    "verification_passed": true
}
```

#### 7. ErrorEvent
Emitted when an error occurs.

```json
{
    "event_id": "uuid",
    "timestamp": "2024-01-15T10:35:00Z",
    "event_type": "error",
    "session_id": "session-uuid",
    "run_id": "run-uuid",
    "error_code": "EXECUTOR_TIMEOUT",
    "error_message": "Command execution timed out after 30 seconds",
    "recoverable": true,
    "step_number": 5
}
```

---

## Executor Client Contract

The core library communicates with `redteam-agent-executor` via HTTP.

### Base URL
```
http://executor-service:8001/api/v1
```

### Endpoints Called by Core

#### POST /execute
Execute a command and return result.

**Request:**
```json
{
    "session_id": "uuid",
    "run_id": "uuid",
    "command": "curl -X POST https://app.example.com/login -d 'test'",
    "executor_type": "http",
    "target": {
        "url": "https://app.example.com",
        "gcp_project_id": "my-project",
        "gcp_region": "us-central1",
        "gcp_service_name": "my-app"
    },
    "timeout": 30,
    "capture_output": true
}
```

**Response:**
```json
{
    "execution_id": "uuid",
    "exit_code": 0,
    "stdout": "HTTP/1.1 200 OK\n...",
    "stderr": "",
    "duration_ms": 1250,
    "truncated": false
}
```

#### POST /execute/stream
Execute with streaming output (SSE).

**Request:** Same as `/execute`

**Response:** Server-Sent Events stream
```
event: output
data: {"stream": "stdout", "chunk": "HTTP/1.1 200 OK\n"}

event: output
data: {"stream": "stdout", "chunk": "{\"status\": \"success\"}"}

event: complete
data: {"exit_code": 0, "duration_ms": 1250}
```

#### GET /health
Health check.

**Response:**
```json
{
    "status": "healthy",
    "version": "0.1.0"
}
```

---

## Data Models

### AppContext
Passed to chains for context about the target application.

```python
class AppContext(BaseModel):
    app_name: str
    app_description: str
    app_url: str

    # From document processing
    tech_stack: TechStackInfo
    architecture: ArchitectureInfo

    # GCP container info
    gcp_project_id: str
    gcp_region: str
    gcp_service_name: str

    # GitHub info
    github_org: str
    github_repo: str
    github_default_branch: str = "main"

    # User info
    user_email: str
    session_id: str

class TechStackInfo(BaseModel):
    languages: list[str]           # ["python", "javascript"]
    frameworks: list[str]          # ["fastapi", "react"]
    databases: list[str]           # ["postgresql", "redis"]
    cloud_services: list[str]      # ["gcp-cloud-run", "gcp-cloud-sql"]

class ArchitectureInfo(BaseModel):
    components: list[Component]
    data_flows: list[DataFlow]
    entry_points: list[EntryPoint]
    authentication_type: str | None

class Component(BaseModel):
    name: str
    type: str                      # "api", "database", "cache", "frontend"
    description: str

class DataFlow(BaseModel):
    source: str
    destination: str
    data_type: str
    protocol: str

class EntryPoint(BaseModel):
    url: str
    method: str
    description: str
    authentication_required: bool
```

### SecurityIssue
Output from security-use scanner.

```python
class SecurityIssue(BaseModel):
    id: str
    severity: Severity              # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str                   # SQL_INJECTION, XSS, SSRF, etc.
    title: str
    description: str
    file_path: str | None
    line_number: int | None
    code_snippet: str | None
    cwe_id: str | None
    remediation_hint: str

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
```

### ChainStep
A single step in an exploit or remediation chain.

```python
class ChainStep(BaseModel):
    step_number: int
    chain_type: ChainType          # EXPLOIT, REMEDIATION
    reasoning: str                  # From LLM <think> tags
    command: str                    # Command to execute
    expected_outcome: str
    success_criteria: str
    status: StepStatus
    output: str | None
    duration_ms: int | None

class ChainType(str, Enum):
    EXPLOIT = "exploit"
    REMEDIATION = "remediation"

class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
```

### ExploitResult
Result of an exploit chain execution.

```python
class ExploitResult(BaseModel):
    success: bool
    vulnerability: SecurityIssue
    steps_executed: list[ChainStep]
    total_steps: int
    evidence: str | None           # Proof of exploitation
    impact: str | None             # What was accessed/achieved
```

### RemediationResult
Result of a remediation chain execution.

```python
class RemediationResult(BaseModel):
    success: bool
    exploit: ExploitResult
    code_fixes: list[CodeFix]
    verification_passed: bool
    attempts: int

class CodeFix(BaseModel):
    file_path: str
    original_code: str
    fixed_code: str
    diff: str
    explanation: str
```

---

## Error Handling

### Error Codes

| Code | Description | Recoverable |
|------|-------------|-------------|
| `LLM_ERROR` | OpenRouter API error | Yes (retry with fallback) |
| `LLM_RATE_LIMIT` | Rate limited by OpenRouter | Yes (wait and retry) |
| `EXECUTOR_TIMEOUT` | Command timed out | Yes (skip step) |
| `EXECUTOR_ERROR` | Executor service error | Depends |
| `DOCUMENT_PARSE_ERROR` | Reducto failed to parse | No |
| `SCANNER_ERROR` | security-use failed | No |
| `CHAIN_MAX_STEPS` | Hit 30 step limit | No |
| `VERIFICATION_FAILED` | Fix didn't work after max attempts | No |

### Exception Classes

```python
class RedTeamAgentError(Exception):
    """Base exception for all core errors"""
    error_code: str
    recoverable: bool

class LLMError(RedTeamAgentError):
    error_code = "LLM_ERROR"
    recoverable = True

class ExecutorError(RedTeamAgentError):
    error_code = "EXECUTOR_ERROR"
    recoverable = False

class ChainError(RedTeamAgentError):
    error_code = "CHAIN_ERROR"
    recoverable = False
```

---

## Integration Example

```python
# How the API service uses this library

from redteam_agent_core import RedTeamAgent
from redteam_agent_core.config import Settings
from redteam_agent_core.models.events import AgentEvent

async def run_agent_pipeline(session_data: dict, websocket_broadcast: Callable):
    settings = Settings()
    agent = RedTeamAgent(settings)

    # Configure executor client
    agent.set_executor_url("http://executor-service:8001")

    # Build app context from session data
    app_context = await agent.build_context(
        app_name=session_data["app_name"],
        app_url=session_data["app_url"],
        documents=session_data["documents"],
        gcp_info=session_data["gcp"],
        github_info=session_data["github"],
        user_email=session_data["user_email"]
    )

    # Stream events to WebSocket
    async for event in agent.run_full_pipeline(app_context):
        await websocket_broadcast(event.model_dump())

        if event.event_type == "remediation_result" and event.success:
            # Create PR
            pr_url = await create_github_pr(event.code_fixes)
            # Send email
            await send_completion_email(session_data["user_email"], pr_url)
```
