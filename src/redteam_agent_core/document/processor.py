"""
Reducto document processor for extracting architecture information.

Reducto (https://reducto.ai) is used to:
1. Parse PDF documents (architecture diagrams, tech specs)
2. Extract text and structure from images
3. Understand diagrams and extract component information

API Reference: https://docs.reducto.ai/api-reference/parse
"""

import json
from enum import Enum
from typing import Any

import httpx
import structlog
from pydantic import BaseModel
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ..config import Settings
from ..models.app_context import (
    ArchitectureInfo,
    Component,
    DataFlow,
    EntryPoint,
    TechStackInfo,
)

logger = structlog.get_logger(__name__)


class DocType(str, Enum):
    """Type of document being processed."""

    ARCHITECTURE_DIAGRAM = "architecture_diagram"
    TECH_SPEC = "tech_spec"
    API_DOC = "api_doc"
    GENERAL = "general"


class ProcessedDocument(BaseModel):
    """Result of processing a document with Reducto."""

    filename: str
    doc_type: DocType
    raw_text: str
    extracted_data: dict[str, Any]
    tech_stack: TechStackInfo | None = None
    architecture: ArchitectureInfo | None = None


class ReductoProcessor:
    """
    Document processor using Reducto API.

    Processes uploaded documents to extract:
    - Technology stack information
    - Architecture diagrams and components
    - API entry points
    - Data flows
    """

    def __init__(self, settings: Settings):
        """
        Initialize the Reducto processor.

        Args:
            settings: Application settings with API key
        """
        self.api_key = settings.REDUCTO_API_KEY
        self.base_url = settings.REDUCTO_BASE_URL

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def _call_reducto(
        self,
        endpoint: str,
        file_content: bytes,
        filename: str,
        options: dict | None = None,
    ) -> dict:
        """
        Make a call to the Reducto API.

        Args:
            endpoint: API endpoint path
            file_content: File bytes to upload
            filename: Original filename
            options: Additional options for the API

        Returns:
            API response as dict
        """
        async with httpx.AsyncClient() as client:
            # Determine content type from filename
            content_type = self._get_content_type(filename)

            files = {
                "file": (filename, file_content, content_type),
            }

            data = options or {}

            logger.debug(
                "calling_reducto",
                endpoint=endpoint,
                filename=filename,
                content_type=content_type,
            )

            response = await client.post(
                f"{self.base_url}{endpoint}",
                headers={"Authorization": f"Bearer {self.api_key}"},
                files=files,
                data=data,
                timeout=120.0,  # Documents can take time to process
            )

            response.raise_for_status()
            return response.json()

    def _get_content_type(self, filename: str) -> str:
        """Get content type based on file extension."""
        ext = filename.lower().split(".")[-1] if "." in filename else ""
        content_types = {
            "pdf": "application/pdf",
            "png": "image/png",
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "gif": "image/gif",
            "webp": "image/webp",
            "md": "text/markdown",
            "txt": "text/plain",
        }
        return content_types.get(ext, "application/octet-stream")

    async def process_document(
        self,
        file_content: bytes,
        filename: str,
        doc_type: DocType = DocType.GENERAL,
    ) -> ProcessedDocument:
        """
        Process a document and extract structured information.

        Args:
            file_content: Raw file bytes
            filename: Original filename
            doc_type: Type of document for specialized processing

        Returns:
            ProcessedDocument with extracted information
        """
        logger.info("processing_document", filename=filename, doc_type=doc_type)

        # Call Reducto parse API
        result = await self._call_reducto(
            endpoint="/v1/parse",
            file_content=file_content,
            filename=filename,
            options={
                "extract_tables": "true",
                "extract_images": "true",
                "ocr": "true",
            },
        )

        raw_text = result.get("text", "")
        extracted_data = result.get("extracted", {})

        # Process based on document type
        tech_stack = None
        architecture = None

        if doc_type in (DocType.ARCHITECTURE_DIAGRAM, DocType.TECH_SPEC):
            tech_stack = self._extract_tech_stack(raw_text, extracted_data)
            architecture = self._extract_architecture(raw_text, extracted_data)
        elif doc_type == DocType.API_DOC:
            architecture = self._extract_api_info(raw_text, extracted_data)

        return ProcessedDocument(
            filename=filename,
            doc_type=doc_type,
            raw_text=raw_text,
            extracted_data=extracted_data,
            tech_stack=tech_stack,
            architecture=architecture,
        )

    async def process_multiple(
        self,
        documents: list[tuple[bytes, str, DocType]],
    ) -> list[ProcessedDocument]:
        """
        Process multiple documents.

        Args:
            documents: List of (content, filename, doc_type) tuples

        Returns:
            List of ProcessedDocument objects
        """
        results = []
        for content, filename, doc_type in documents:
            try:
                result = await self.process_document(content, filename, doc_type)
                results.append(result)
            except Exception as e:
                logger.error("document_processing_failed", filename=filename, error=str(e))
                # Continue processing other documents
        return results

    def _extract_tech_stack(
        self,
        raw_text: str,
        extracted_data: dict,
    ) -> TechStackInfo:
        """
        Extract technology stack information from document text.

        Uses pattern matching and extracted data to identify technologies.
        """
        text_lower = raw_text.lower()

        # Known technologies to look for
        languages = self._find_matches(
            text_lower,
            ["python", "javascript", "typescript", "go", "golang", "java", "rust", "ruby", "php", "c#", "kotlin"],
        )

        frameworks = self._find_matches(
            text_lower,
            ["fastapi", "django", "flask", "express", "react", "vue", "angular", "next.js", "nest.js", "gin", "spring", "rails"],
        )

        databases = self._find_matches(
            text_lower,
            ["postgresql", "postgres", "mysql", "mongodb", "redis", "elasticsearch", "dynamodb", "firestore", "sqlite", "cassandra"],
        )

        cloud_services = self._find_matches(
            text_lower,
            ["cloud run", "gcp", "aws", "azure", "kubernetes", "k8s", "docker", "lambda", "ec2", "s3", "gcs", "cloud storage"],
        )

        auth_methods = self._find_matches(
            text_lower,
            ["jwt", "oauth", "oauth2", "openid", "saml", "session", "api key", "basic auth", "bearer token"],
        )

        return TechStackInfo(
            languages=languages,
            frameworks=frameworks,
            databases=databases,
            cloud_services=cloud_services,
            authentication=auth_methods,
            other=[],
        )

    def _extract_architecture(
        self,
        raw_text: str,
        extracted_data: dict,
    ) -> ArchitectureInfo:
        """
        Extract architecture information from document.

        Identifies components, data flows, and entry points.
        """
        components = []
        data_flows = []
        entry_points = []
        auth_type = None

        # Look for common component patterns
        component_patterns = [
            ("api", "API Gateway"),
            ("backend", "Backend Service"),
            ("frontend", "Frontend Application"),
            ("database", "Database"),
            ("cache", "Cache Layer"),
            ("queue", "Message Queue"),
            ("worker", "Background Worker"),
            ("auth", "Authentication Service"),
        ]

        text_lower = raw_text.lower()
        for pattern, name in component_patterns:
            if pattern in text_lower:
                components.append(
                    Component(
                        name=name,
                        type=pattern,
                        description=f"Detected {name} component",
                    )
                )

        # Try to extract from structured data if available
        if "components" in extracted_data:
            for comp in extracted_data["components"]:
                components.append(
                    Component(
                        name=comp.get("name", "Unknown"),
                        type=comp.get("type", "unknown"),
                        description=comp.get("description", ""),
                        technology=comp.get("technology"),
                    )
                )

        if "data_flows" in extracted_data:
            for flow in extracted_data["data_flows"]:
                data_flows.append(
                    DataFlow(
                        source=flow.get("source", "unknown"),
                        destination=flow.get("destination", "unknown"),
                        data_type=flow.get("data_type", "unknown"),
                        protocol=flow.get("protocol", "https"),
                        encrypted=flow.get("encrypted", True),
                    )
                )

        if "entry_points" in extracted_data:
            for ep in extracted_data["entry_points"]:
                entry_points.append(
                    EntryPoint(
                        url=ep.get("url", "/"),
                        method=ep.get("method", "GET"),
                        description=ep.get("description", ""),
                        authentication_required=ep.get("auth_required", False),
                        parameters=ep.get("parameters", []),
                        request_body_type=ep.get("body_type"),
                    )
                )

        # Detect authentication type
        if "jwt" in text_lower or "json web token" in text_lower:
            auth_type = "jwt"
        elif "oauth" in text_lower:
            auth_type = "oauth2"
        elif "session" in text_lower:
            auth_type = "session"

        return ArchitectureInfo(
            components=components,
            data_flows=data_flows,
            entry_points=entry_points,
            authentication_type=auth_type,
            notes=None,
        )

    def _extract_api_info(
        self,
        raw_text: str,
        extracted_data: dict,
    ) -> ArchitectureInfo:
        """
        Extract API endpoint information from API documentation.
        """
        entry_points = []

        # Look for common API patterns in text
        lines = raw_text.split("\n")
        for line in lines:
            line_upper = line.upper().strip()
            for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                if line_upper.startswith(method):
                    # Try to extract the path
                    parts = line.split()
                    if len(parts) >= 2:
                        entry_points.append(
                            EntryPoint(
                                url=parts[1],
                                method=method,
                                description=" ".join(parts[2:]) if len(parts) > 2 else "",
                                authentication_required=False,
                            )
                        )

        # Also use extracted data if available
        if "endpoints" in extracted_data:
            for ep in extracted_data["endpoints"]:
                entry_points.append(
                    EntryPoint(
                        url=ep.get("path", "/"),
                        method=ep.get("method", "GET"),
                        description=ep.get("description", ""),
                        authentication_required=ep.get("auth", False),
                        parameters=ep.get("params", []),
                        request_body_type=ep.get("body_type"),
                    )
                )

        return ArchitectureInfo(
            components=[],
            data_flows=[],
            entry_points=entry_points,
            authentication_type=None,
        )

    def _find_matches(self, text: str, patterns: list[str]) -> list[str]:
        """Find which patterns exist in the text."""
        found = []
        for pattern in patterns:
            if pattern in text:
                found.append(pattern)
        return found

    def merge_results(
        self,
        documents: list[ProcessedDocument],
    ) -> tuple[TechStackInfo, ArchitectureInfo]:
        """
        Merge results from multiple documents into unified info.

        Args:
            documents: List of processed documents

        Returns:
            Tuple of (merged TechStackInfo, merged ArchitectureInfo)
        """
        # Merge tech stacks
        all_languages = set()
        all_frameworks = set()
        all_databases = set()
        all_cloud_services = set()
        all_auth = set()

        for doc in documents:
            if doc.tech_stack:
                all_languages.update(doc.tech_stack.languages)
                all_frameworks.update(doc.tech_stack.frameworks)
                all_databases.update(doc.tech_stack.databases)
                all_cloud_services.update(doc.tech_stack.cloud_services)
                all_auth.update(doc.tech_stack.authentication)

        merged_tech_stack = TechStackInfo(
            languages=list(all_languages),
            frameworks=list(all_frameworks),
            databases=list(all_databases),
            cloud_services=list(all_cloud_services),
            authentication=list(all_auth),
        )

        # Merge architectures
        all_components = []
        all_data_flows = []
        all_entry_points = []
        auth_type = None

        for doc in documents:
            if doc.architecture:
                all_components.extend(doc.architecture.components)
                all_data_flows.extend(doc.architecture.data_flows)
                all_entry_points.extend(doc.architecture.entry_points)
                if doc.architecture.authentication_type:
                    auth_type = doc.architecture.authentication_type

        # Deduplicate components by name
        seen_names = set()
        unique_components = []
        for comp in all_components:
            if comp.name not in seen_names:
                seen_names.add(comp.name)
                unique_components.append(comp)

        merged_architecture = ArchitectureInfo(
            components=unique_components,
            data_flows=all_data_flows,
            entry_points=all_entry_points,
            authentication_type=auth_type,
        )

        return merged_tech_stack, merged_architecture
