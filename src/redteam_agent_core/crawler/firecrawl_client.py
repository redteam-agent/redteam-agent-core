"""
Firecrawl integration for crawling exploit databases in real-time.

This module crawls open source vulnerability databases:
- Exploit-DB (https://www.exploit-db.com/)
- NVD - National Vulnerability Database (https://nvd.nist.gov/)
- OWASP Cheat Sheets (https://cheatsheetseries.owasp.org/)
- PacketStorm Security (https://packetstormsecurity.com/)

The crawled data is used to provide context to GLM-4.7 for exploit generation.
"""

import asyncio
from datetime import datetime, timedelta
from typing import AsyncIterator

import httpx
from diskcache import Cache
from pydantic import BaseModel

from ..config import Settings
from ..models.vulnerability import Severity, VulnerabilityInfo, VulnerabilityKnowledgeBase


class CrawlProgress(BaseModel):
    """Progress update during crawling."""

    source: str
    status: str  # "starting", "crawling", "parsing", "complete", "error"
    items_found: int
    message: str


class FirecrawlClient:
    """
    Client for crawling exploit databases using Firecrawl.

    Firecrawl API: https://docs.firecrawl.dev/

    This client crawls vulnerability databases in real-time and
    builds a knowledge base for the LLM to use during exploit generation.
    """

    # Open source exploit databases to crawl
    EXPLOIT_SOURCES = {
        "exploit-db": {
            "base_url": "https://www.exploit-db.com",
            "search_url": "https://www.exploit-db.com/search",
            "description": "Exploit Database - archive of exploits and vulnerable software",
        },
        "nvd": {
            "base_url": "https://nvd.nist.gov",
            "search_url": "https://nvd.nist.gov/vuln/search",
            "description": "National Vulnerability Database - US government CVE repository",
        },
        "owasp": {
            "base_url": "https://cheatsheetseries.owasp.org",
            "index_url": "https://cheatsheetseries.owasp.org/IndexASVS.html",
            "description": "OWASP Cheat Sheet Series - security best practices",
        },
        "packetstorm": {
            "base_url": "https://packetstormsecurity.com",
            "search_url": "https://packetstormsecurity.com/search",
            "description": "PacketStorm Security - exploits and security tools",
        },
    }

    def __init__(self, settings: Settings):
        """Initialize the Firecrawl client."""
        self.api_key = settings.FIRECRAWL_API_KEY
        self.base_url = settings.FIRECRAWL_BASE_URL
        self.cache = Cache(settings.CACHE_DIR + "/firecrawl")
        self.cache_ttl = timedelta(hours=settings.CACHE_TTL_HOURS)

    async def crawl_for_vulnerabilities(
        self,
        tech_stack: list[str],
        vulnerability_types: list[str],
        cwe_ids: list[str] | None = None,
    ) -> AsyncIterator[CrawlProgress]:
        """
        Crawl exploit databases for relevant vulnerabilities.

        This method is called during the pipeline to gather exploit
        information relevant to the target application.

        Args:
            tech_stack: Technologies used by the target (e.g., ["python", "django"])
            vulnerability_types: Types to search for (e.g., ["sql_injection", "xss"])
            cwe_ids: Specific CWE IDs to search for

        Yields:
            CrawlProgress updates for real-time frontend display
        """
        all_vulns: list[VulnerabilityInfo] = []

        for source_name, source_config in self.EXPLOIT_SOURCES.items():
            yield CrawlProgress(
                source=source_name,
                status="starting",
                items_found=0,
                message=f"Starting crawl of {source_config['description']}",
            )

            try:
                vulns = await self._crawl_source(
                    source_name=source_name,
                    source_config=source_config,
                    tech_stack=tech_stack,
                    vulnerability_types=vulnerability_types,
                    cwe_ids=cwe_ids,
                )

                all_vulns.extend(vulns)

                yield CrawlProgress(
                    source=source_name,
                    status="complete",
                    items_found=len(vulns),
                    message=f"Found {len(vulns)} relevant entries from {source_name}",
                )

            except Exception as e:
                yield CrawlProgress(
                    source=source_name,
                    status="error",
                    items_found=0,
                    message=f"Error crawling {source_name}: {str(e)}",
                )

        # Cache the complete knowledge base
        cache_key = self._build_cache_key(tech_stack, vulnerability_types)
        self.cache.set(
            cache_key,
            VulnerabilityKnowledgeBase(
                vulnerabilities=all_vulns,
                crawled_at=datetime.utcnow().isoformat(),
                sources=list(self.EXPLOIT_SOURCES.keys()),
            ).model_dump(),
            expire=self.cache_ttl.total_seconds(),
        )

    async def get_knowledge_base(
        self,
        tech_stack: list[str],
        vulnerability_types: list[str],
        cwe_ids: list[str] | None = None,
        force_refresh: bool = False,
    ) -> VulnerabilityKnowledgeBase:
        """
        Get the vulnerability knowledge base, crawling if necessary.

        Args:
            tech_stack: Technologies to search for
            vulnerability_types: Vulnerability types to search for
            cwe_ids: Specific CWE IDs
            force_refresh: Force a fresh crawl even if cached

        Returns:
            VulnerabilityKnowledgeBase with all relevant vulnerabilities
        """
        cache_key = self._build_cache_key(tech_stack, vulnerability_types)

        # Check cache first
        if not force_refresh:
            cached = self.cache.get(cache_key)
            if cached:
                return VulnerabilityKnowledgeBase.model_validate(cached)

        # Crawl and collect all results
        all_vulns: list[VulnerabilityInfo] = []
        async for progress in self.crawl_for_vulnerabilities(
            tech_stack, vulnerability_types, cwe_ids
        ):
            pass  # Progress is yielded, we just need the final result

        # Return from cache (it was set during crawling)
        cached = self.cache.get(cache_key)
        if cached:
            return VulnerabilityKnowledgeBase.model_validate(cached)

        return VulnerabilityKnowledgeBase(
            vulnerabilities=[],
            crawled_at=datetime.utcnow().isoformat(),
            sources=[],
        )

    async def _crawl_source(
        self,
        source_name: str,
        source_config: dict,
        tech_stack: list[str],
        vulnerability_types: list[str],
        cwe_ids: list[str] | None,
    ) -> list[VulnerabilityInfo]:
        """Crawl a single exploit database source."""
        vulns = []

        async with httpx.AsyncClient() as client:
            # Build search queries
            queries = self._build_search_queries(
                tech_stack, vulnerability_types, cwe_ids
            )

            for query in queries:
                # Use Firecrawl to crawl and extract data
                response = await client.post(
                    f"{self.base_url}/v1/scrape",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "url": self._build_search_url(source_name, source_config, query),
                        "formats": ["markdown", "extract"],
                        "extract": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "vulnerabilities": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "title": {"type": "string"},
                                                "description": {"type": "string"},
                                                "cve_id": {"type": "string"},
                                                "cwe_id": {"type": "string"},
                                                "severity": {"type": "string"},
                                                "affected_software": {"type": "string"},
                                                "exploit_code": {"type": "string"},
                                                "remediation": {"type": "string"},
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                    timeout=60.0,
                )

                if response.status_code == 200:
                    data = response.json()
                    extracted = data.get("data", {}).get("extract", {})
                    for item in extracted.get("vulnerabilities", []):
                        vulns.append(self._parse_vulnerability(item, source_name))

                # Rate limiting
                await asyncio.sleep(0.5)

        return vulns

    def _build_search_queries(
        self,
        tech_stack: list[str],
        vulnerability_types: list[str],
        cwe_ids: list[str] | None,
    ) -> list[str]:
        """Build search queries from input parameters."""
        queries = []

        # Combine tech stack with vulnerability types
        for tech in tech_stack[:3]:  # Limit to avoid too many requests
            for vuln_type in vulnerability_types[:3]:
                queries.append(f"{tech} {vuln_type}")

        # Add CWE-specific queries
        if cwe_ids:
            for cwe in cwe_ids[:5]:
                queries.append(cwe)

        return queries

    def _build_search_url(
        self,
        source_name: str,
        source_config: dict,
        query: str,
    ) -> str:
        """Build the search URL for a source."""
        if source_name == "exploit-db":
            return f"{source_config['search_url']}?q={query}"
        elif source_name == "nvd":
            return f"{source_config['search_url']}?query={query}"
        elif source_name == "packetstorm":
            return f"{source_config['search_url']}/?q={query}"
        else:
            return source_config.get("index_url", source_config["base_url"])

    def _parse_vulnerability(
        self,
        item: dict,
        source: str,
    ) -> VulnerabilityInfo:
        """Parse a crawled vulnerability into our model."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }

        return VulnerabilityInfo(
            cve_id=item.get("cve_id"),
            cwe_id=item.get("cwe_id"),
            title=item.get("title", "Unknown"),
            description=item.get("description", ""),
            severity=severity_map.get(
                item.get("severity", "medium").lower(),
                Severity.MEDIUM,
            ),
            affected_technologies=[item.get("affected_software", "")],
            exploitation_techniques=[],
            proof_of_concepts=[item.get("exploit_code", "")] if item.get("exploit_code") else [],
            remediation=item.get("remediation", ""),
            references=[],
            source=source,
        )

    def _build_cache_key(
        self,
        tech_stack: list[str],
        vulnerability_types: list[str],
    ) -> str:
        """Build a cache key from search parameters."""
        tech_part = "-".join(sorted(tech_stack))
        vuln_part = "-".join(sorted(vulnerability_types))
        return f"kb:{tech_part}:{vuln_part}"
