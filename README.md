# RedTeam Agent Core

Core Python library for the RedTeam Agent platform. Contains LLM integration, document processing, vulnerability scanning, and exploit/remediation chain engines.

## Overview

This library provides the core functionality for automated security testing:

- **LLM Provider**: OpenRouter integration with GLM-4.7 as primary model
- **Document Processing**: Reducto integration for parsing architecture diagrams and technical docs
- **Vulnerability Crawling**: Firecrawl integration for crawling NVD, Exploit-DB, OWASP
- **Security Scanning**: security-use integration for initial vulnerability assessment
- **Exploit Chain Engine**: Autonomous exploit generation and execution (up to 30 steps)
- **Remediation Chain Engine**: Automatic code fixing and verification

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      redteam-agent-core                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ LLM Provider│  │  Document   │  │   Vulnerability         │  │
│  │ (OpenRouter)│  │  Processor  │  │   Knowledge Base        │  │
│  │  GLM-4.7    │  │  (Reducto)  │  │   (Firecrawl)          │  │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘  │
│         │                │                     │                 │
│         └────────────────┼─────────────────────┘                 │
│                          ▼                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Chain Engine                            │  │
│  │  ┌─────────────────┐        ┌─────────────────────────┐   │  │
│  │  │  Exploit Chain  │───────▶│  Remediation Chain      │   │  │
│  │  │  (30 max steps) │        │  (fix → test → verify)  │   │  │
│  │  └─────────────────┘        └─────────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                          │                                       │
│                          ▼                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                   Event Emitter                            │  │
│  │  (Streams reasoning, commands, results to API layer)      │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

```bash
pip install redteam-agent-core
# or with poetry
poetry add redteam-agent-core
```

## Usage

```python
from redteam_agent_core import RedTeamAgent
from redteam_agent_core.config import Settings

settings = Settings()
agent = RedTeamAgent(settings)

# Process documents
app_context = await agent.process_documents(
    app_name="MyApp",
    app_url="https://myapp.example.com",
    documents=[arch_diagram_pdf, tech_spec_doc]
)

# Run security scan
scan_results = await agent.scan(app_context)

# Execute exploit chain
async for event in agent.run_exploit_chain(app_context, scan_results):
    if event.type == "reasoning":
        print(f"Reasoning: {event.text}")
    elif event.type == "command":
        print(f"Command: {event.command}")
    elif event.type == "exploit_success":
        # Run remediation
        async for fix_event in agent.run_remediation_chain(event.exploit):
            print(fix_event)
```

## Configuration

Environment variables:

```bash
OPENROUTER_API_KEY=sk-or-...      # Required
REDUCTO_API_KEY=...                # Required
FIRECRAWL_API_KEY=...              # Required
```

## Directory Structure

```
src/redteam_agent_core/
├── __init__.py
├── agent.py                 # Main RedTeamAgent class
├── config.py                # Pydantic Settings
├── llm/
│   ├── __init__.py
│   ├── base.py              # BaseLLMProvider abstract class
│   ├── openrouter.py        # OpenRouter implementation
│   └── prompts.py           # System prompts for chains
├── document/
│   ├── __init__.py
│   ├── processor.py         # Reducto integration
│   └── schemas.py           # Document models
├── scanner/
│   ├── __init__.py
│   ├── security_use.py      # security-use wrapper
│   └── models.py            # Vulnerability models
├── crawler/
│   ├── __init__.py
│   ├── firecrawl.py         # Firecrawl client
│   └── knowledge_base.py    # Aggregated vuln database
├── chains/
│   ├── __init__.py
│   ├── base.py              # BaseChain class
│   ├── exploit.py           # ExploitChain (30 steps max)
│   ├── remediation.py       # RemediationChain
│   └── reasoning.py         # Reasoning extraction
├── executor/
│   ├── __init__.py
│   └── client.py            # Client for executor service
├── models/
│   ├── __init__.py
│   ├── app_context.py       # Application context
│   ├── events.py            # Event types for streaming
│   └── results.py           # Chain results
└── events/
    ├── __init__.py
    └── emitter.py           # Event streaming
```

## Integration Points

### With redteam-agent-api
- This library is imported and used by the API service
- Events are streamed to WebSocket connections via the event emitter

### With redteam-agent-executor
- Commands are sent to the executor service via HTTP
- Uses `ExecutorClient` to communicate with executor

## Development

```bash
# Install dependencies
poetry install

# Run tests
poetry run pytest

# Type checking
poetry run mypy src/

# Linting
poetry run ruff check src/
```

## License

MIT
