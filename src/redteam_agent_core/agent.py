"""
Main RedTeamAgent class - orchestrates the entire security testing pipeline.

This is the primary entry point for the core library. The API service
instantiates this class and calls its methods to run the pipeline.
"""

from typing import AsyncIterator
from uuid import uuid4

import structlog

from .chains import ExploitChain, RemediationChain
from .config import Settings
from .crawler import FirecrawlClient
from .document import DocType, ReductoProcessor
from .events import EventEmitter
from .executor import ExecutorClient, TargetInfo
from .llm import OpenRouterProvider
from .models.app_context import AppContext, ArchitectureInfo, TechStackInfo
from .models.events import AgentEvent, PipelineStage
from .models.results import ExploitResult
from .models.vulnerability import SecurityIssue, VulnerabilityKnowledgeBase
from .scanner import SecurityUseScanner

logger = structlog.get_logger(__name__)


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
        """
        Initialize the agent with configuration.

        Args:
            settings: Application settings with API keys and configuration
        """
        self.settings = settings

        # Initialize components
        self.llm = OpenRouterProvider(settings)
        self.document_processor = ReductoProcessor(settings)
        self.crawler = FirecrawlClient(settings)
        self.scanner = SecurityUseScanner()
        self.executor = ExecutorClient(
            base_url=settings.EXECUTOR_SERVICE_URL,
            timeout=settings.EXECUTOR_TIMEOUT,
        )

        logger.info("agent_initialized")

    def set_executor_url(self, url: str) -> None:
        """
        Override the executor service URL.

        Args:
            url: New executor service URL
        """
        self.executor = ExecutorClient(
            base_url=url,
            timeout=self.settings.EXECUTOR_TIMEOUT,
        )
        logger.info("executor_url_changed", url=url)

    async def build_context(
        self,
        app_name: str,
        app_url: str,
        app_description: str,
        documents: list[tuple[bytes, str]],
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

        Args:
            app_name: Application name
            app_url: Application URL
            app_description: Description of the application
            documents: List of (content, filename) tuples
            gcp_info: GCP deployment information
            github_info: GitHub repository information
            user_email: User's email address
            session_id: Current session ID

        Returns:
            Complete AppContext for pipeline execution
        """
        logger.info(
            "building_context",
            app_name=app_name,
            num_documents=len(documents),
        )

        # Process documents if provided
        tech_stack = TechStackInfo()
        architecture = ArchitectureInfo()

        if documents:
            processed_docs = []

            for content, filename in documents:
                # Determine document type from filename
                if "architect" in filename.lower() or "diagram" in filename.lower():
                    doc_type = DocType.ARCHITECTURE_DIAGRAM
                elif "api" in filename.lower() or "endpoint" in filename.lower():
                    doc_type = DocType.API_DOC
                elif "spec" in filename.lower() or "tech" in filename.lower():
                    doc_type = DocType.TECH_SPEC
                else:
                    doc_type = DocType.GENERAL

                try:
                    doc = await self.document_processor.process_document(
                        file_content=content,
                        filename=filename,
                        doc_type=doc_type,
                    )
                    processed_docs.append(doc)
                except Exception as e:
                    logger.warning(
                        "document_processing_failed",
                        filename=filename,
                        error=str(e),
                    )

            # Merge results from all documents
            if processed_docs:
                tech_stack, architecture = self.document_processor.merge_results(
                    processed_docs
                )

        # Create the app context
        run_id = str(uuid4())

        return AppContext(
            app_name=app_name,
            app_description=app_description,
            app_url=app_url,
            tech_stack=tech_stack,
            architecture=architecture,
            gcp_project_id=gcp_info.get("project_id", ""),
            gcp_region=gcp_info.get("region", ""),
            gcp_service_name=gcp_info.get("service_name", ""),
            gcp_container_url=gcp_info.get("container_url", app_url),
            github_org=github_info.get("org", ""),
            github_repo=github_info.get("repo", ""),
            github_default_branch=github_info.get("default_branch", "main"),
            user_email=user_email,
            session_id=session_id,
            run_id=run_id,
        )

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
        logger.info(
            "starting_pipeline",
            app_name=app_context.app_name,
            session_id=app_context.session_id,
        )

        # Create event emitter
        emitter = EventEmitter(
            session_id=app_context.session_id,
            run_id=app_context.run_id or "",
        )

        try:
            # Stage 1: Crawl vulnerability databases
            await emitter.set_stage(
                PipelineStage.CRAWLING_VULNERABILITIES,
                "Crawling exploit databases...",
            )

            # Determine technologies to search for
            tech_stack = (
                app_context.tech_stack.languages
                + app_context.tech_stack.frameworks
            )
            vulnerability_types = ["sql_injection", "xss", "ssrf", "idor"]

            async for progress in self.crawler.crawl_for_vulnerabilities(
                tech_stack=tech_stack,
                vulnerability_types=vulnerability_types,
            ):
                # Yield crawler progress as events
                yield await self._progress_to_event(emitter, progress)

            knowledge_base = await self.crawler.get_knowledge_base(
                tech_stack=tech_stack,
                vulnerability_types=vulnerability_types,
            )

            logger.info(
                "crawling_complete",
                vulnerabilities_found=len(knowledge_base.vulnerabilities),
            )

            # Stage 2: Run security scanner
            await emitter.set_stage(
                PipelineStage.SCANNING,
                "Scanning for vulnerabilities...",
            )

            vulnerabilities = await self.scanner.scan_url(
                target_url=app_context.app_url,
                scan_type="full",
            )

            logger.info(
                "scanning_complete",
                vulnerabilities_found=len(vulnerabilities),
            )

            if not vulnerabilities:
                await emitter.set_stage(
                    PipelineStage.COMPLETED,
                    "No vulnerabilities found. Security assessment complete!",
                )
                return

            # Stage 3: Exploit chains for each vulnerability
            await emitter.set_stage(
                PipelineStage.EXPLOITING,
                f"Testing {len(vulnerabilities)} vulnerabilities...",
            )

            successful_exploits: list[ExploitResult] = []

            for vuln in vulnerabilities:
                async for event in self._run_exploit_for_vulnerability(
                    app_context=app_context,
                    vulnerability=vuln,
                    knowledge_base=knowledge_base,
                    emitter=emitter,
                ):
                    yield event

                # Get exploit result
                # Note: In a real implementation, we'd track this better
                exploit_result = getattr(self, "_last_exploit_result", None)
                if exploit_result and exploit_result.success:
                    successful_exploits.append(exploit_result)

            # Stage 4: Remediation for successful exploits
            if successful_exploits:
                await emitter.set_stage(
                    PipelineStage.REMEDIATING,
                    f"Fixing {len(successful_exploits)} vulnerabilities...",
                )

                for exploit_result in successful_exploits:
                    async for event in self._run_remediation_for_exploit(
                        app_context=app_context,
                        exploit_result=exploit_result,
                        emitter=emitter,
                    ):
                        yield event

            # Stage 5: Complete
            await emitter.set_stage(
                PipelineStage.COMPLETED,
                "Security assessment complete!",
            )

        except Exception as e:
            logger.error("pipeline_failed", error=str(e))
            await emitter.set_stage(
                PipelineStage.FAILED,
                f"Pipeline failed: {str(e)}",
            )
            await emitter.emit_error(
                error_code="PIPELINE_ERROR",
                error_message=str(e),
                recoverable=False,
            )
            raise

        finally:
            await emitter.close()

    async def _run_exploit_for_vulnerability(
        self,
        app_context: AppContext,
        vulnerability: SecurityIssue,
        knowledge_base: VulnerabilityKnowledgeBase,
        emitter: EventEmitter,
    ) -> AsyncIterator[AgentEvent]:
        """Run exploit chain for a single vulnerability."""
        logger.info(
            "exploiting_vulnerability",
            vulnerability_id=vulnerability.id,
            category=vulnerability.category,
        )

        exploit_chain = ExploitChain(
            llm=self.llm,
            emitter=emitter,
            max_steps=self.settings.MAX_EXPLOIT_STEPS,
        )

        async for step in exploit_chain.run_chain(
            app_context=app_context,
            vulnerability=vulnerability,
            knowledge_base=knowledge_base,
            executor=self.executor,
        ):
            # Yield buffered events
            for event in emitter.get_buffered_events():
                yield event
            emitter.clear_buffer()

        # Store the result for remediation
        self._last_exploit_result = exploit_chain.result

    async def _run_remediation_for_exploit(
        self,
        app_context: AppContext,
        exploit_result: ExploitResult,
        emitter: EventEmitter,
    ) -> AsyncIterator[AgentEvent]:
        """Run remediation chain for a successful exploit."""
        logger.info(
            "remediating_vulnerability",
            vulnerability_id=exploit_result.vulnerability_id,
        )

        # In a real implementation, we'd fetch the codebase from GitHub
        # For now, we'll use an empty codebase
        codebase: dict[str, str] = {}

        target = TargetInfo(
            url=app_context.app_url,
            gcp_project_id=app_context.gcp_project_id,
            gcp_region=app_context.gcp_region,
            gcp_service_name=app_context.gcp_service_name,
        )

        remediation_chain = RemediationChain(
            llm=self.llm,
            emitter=emitter,
            max_attempts=self.settings.MAX_REMEDIATION_ATTEMPTS,
        )

        async for step in remediation_chain.run_remediation(
            exploit_result=exploit_result,
            codebase=codebase,
            executor=self.executor,
            target=target,
            session_id=app_context.session_id,
            run_id=app_context.run_id or "",
        ):
            # Yield buffered events
            for event in emitter.get_buffered_events():
                yield event
            emitter.clear_buffer()

    async def _progress_to_event(
        self,
        emitter: EventEmitter,
        progress,
    ) -> AgentEvent:
        """Convert crawler progress to an event."""
        from .crawler import CrawlProgress

        # Emit as an output event for the right panel
        await emitter.emit_output(
            step_number=0,
            output=f"[{progress.source}] {progress.message}",
            stream="stdout",
        )

        # Return the last emitted event
        events = emitter.get_buffered_events()
        return events[-1] if events else None

    async def run_exploit_chain(
        self,
        app_context: AppContext,
        vulnerability: SecurityIssue,
        knowledge_base: VulnerabilityKnowledgeBase,
    ) -> AsyncIterator[AgentEvent]:
        """
        Run an exploit chain for a single vulnerability.

        This is called by run_full_pipeline but can also be called directly
        for testing individual vulnerabilities.

        Args:
            app_context: Application context
            vulnerability: Vulnerability to exploit
            knowledge_base: Knowledge base of known exploits

        Yields:
            AgentEvent objects for streaming
        """
        emitter = EventEmitter(
            session_id=app_context.session_id,
            run_id=app_context.run_id or "",
        )

        try:
            async for event in self._run_exploit_for_vulnerability(
                app_context=app_context,
                vulnerability=vulnerability,
                knowledge_base=knowledge_base,
                emitter=emitter,
            ):
                yield event
        finally:
            await emitter.close()

    async def run_remediation_chain(
        self,
        app_context: AppContext,
        exploit_result: ExploitResult,
        codebase: dict[str, str] | None = None,
    ) -> AsyncIterator[AgentEvent]:
        """
        Run a remediation chain for a successful exploit.

        This method:
        1. Generates code fixes using the LLM
        2. Applies fixes to the codebase
        3. Re-runs the exploit to verify it fails
        4. Retries if verification fails (up to max attempts)

        Args:
            app_context: Application context
            exploit_result: The successful exploit to fix
            codebase: Optional codebase dictionary (file_path -> content)

        Yields:
            AgentEvent objects for streaming
        """
        emitter = EventEmitter(
            session_id=app_context.session_id,
            run_id=app_context.run_id or "",
        )

        target = TargetInfo(
            url=app_context.app_url,
            gcp_project_id=app_context.gcp_project_id,
            gcp_region=app_context.gcp_region,
            gcp_service_name=app_context.gcp_service_name,
        )

        remediation_chain = RemediationChain(
            llm=self.llm,
            emitter=emitter,
            max_attempts=self.settings.MAX_REMEDIATION_ATTEMPTS,
        )

        try:
            async for step in remediation_chain.run_remediation(
                exploit_result=exploit_result,
                codebase=codebase or {},
                executor=self.executor,
                target=target,
                session_id=app_context.session_id,
                run_id=app_context.run_id or "",
            ):
                for event in emitter.get_buffered_events():
                    yield event
                emitter.clear_buffer()
        finally:
            await emitter.close()
