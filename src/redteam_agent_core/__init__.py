"""
RedTeam Agent Core Library

Core functionality for automated security testing including:
- LLM integration via OpenRouter (GLM-4.7 primary)
- Document processing via Reducto
- Vulnerability crawling via Firecrawl
- Security scanning via security-use
- Exploit and remediation chain engines
"""

from .agent import RedTeamAgent
from .config import Settings

__version__ = "0.1.0"
__all__ = ["RedTeamAgent", "Settings"]
