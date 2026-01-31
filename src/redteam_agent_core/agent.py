"""
Main RedTeamAgent class - orchestrates the entire security testing pipeline.

This is the primary entry point for the core library. The API service
instantiates this class and calls its methods to run the pipeline.
"""

from typing import AsyncIterator

from .config import Settings
from .models.app_context import AppContext
from .models.events import AgentEvent


class RedTeamAgent:
    """
    Main agent class that orchestrates the security testing pipeline.

    Usage:
        settings = Settings()
        agent = RedTeamAgent(settings)

        # Build context from user input and documents
        ctx = await agent.build_context(...)

        # Run full pipeline and stream events
        async for event in agent.run_full_pipeline(ctx):
            # Handle events (send to WebSocket, etc.)
            pass
    """

    def __init__(self, settings: Settings) -> None:
        """Initialize the agent with configuration."""
        self.settings = settings
        # Components will be initialized here
        # - self.llm = OpenRouterProvider(settings)
        # - self.document_processor = ReductoProcessor(settings)
        # - self.crawler = FirecrawlClient(settings)
        # - self.scanner = SecurityUseClient(settings)
        # - self.executor = ExecutorClient(settings)
        raise NotImplementedError("See Issue #1 for implementation")

    def set_executor_url(self, url: str) -> None:
        """Override the executor service URL."""
        raise NotImplementedError("See Issue #1 for implementation")

    async def build_context(
        self,
        app_name: str,
        app_url: str,
        app_description: str,
        documents: list[bytes],
        gcp_info: dict,
        github_info: dict,
        user_email: str,
        session_id: str,
    ) -> AppContext:
        """
        Build the application context from user input and documents.

        This method:
        1. Processes documents with Reducto to extract architecture info
        2. Builds the TechStackInfo and ArchitectureInfo
        3. Creates the complete AppContext for chain execution
        """
        raise NotImplementedError("See Issue #8 for implementation")

    async def run_full_pipeline(
        self,
        app_context: AppContext,
    ) -> AsyncIterator[AgentEvent]:
        """
        Run the complete security testing pipeline.

        Pipeline stages:
        1. Crawl vulnerability databases (Firecrawl)
        2. Run security scanner (security-use)
        3. Execute exploit chains for each vulnerability
        4. For successful exploits, run remediation chains
        5. Emit completion event

        Yields events for each stage that should be streamed to the frontend.
        """
        raise NotImplementedError("See Issues #4-7 for implementation")

    async def run_exploit_chain(
        self,
        app_context: AppContext,
        vulnerability: "SecurityIssue",
        knowledge_base: list["VulnerabilityInfo"],
    ) -> AsyncIterator[AgentEvent]:
        """
        Run an exploit chain for a single vulnerability.

        This is called by run_full_pipeline but can also be called directly
        for testing individual vulnerabilities.
        """
        raise NotImplementedError("See Issue #6 for implementation")

    async def run_remediation_chain(
        self,
        app_context: AppContext,
        exploit_result: "ExploitResult",
    ) -> AsyncIterator[AgentEvent]:
        """
        Run a remediation chain for a successful exploit.

        This method:
        1. Generates code fixes using the LLM
        2. Applies fixes to the codebase
        3. Re-runs the exploit to verify it fails
        4. Retries if verification fails (up to max attempts)
        """
        raise NotImplementedError("See Issue #7 for implementation")
