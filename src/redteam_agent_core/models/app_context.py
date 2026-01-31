"""Application context models"""

from pydantic import BaseModel


class Component(BaseModel):
    """A component in the application architecture."""

    name: str
    type: str  # "api", "database", "cache", "frontend", "queue", etc.
    description: str
    technology: str | None = None  # e.g., "PostgreSQL", "Redis", "React"


class DataFlow(BaseModel):
    """Data flow between components."""

    source: str  # Component name
    destination: str  # Component name
    data_type: str  # "user_credentials", "session_token", "user_data", etc.
    protocol: str  # "https", "tcp", "grpc", etc.
    encrypted: bool = True


class EntryPoint(BaseModel):
    """An API entry point in the application."""

    url: str  # Full URL or path pattern
    method: str  # HTTP method
    description: str
    authentication_required: bool
    parameters: list[str] = []  # Parameter names
    request_body_type: str | None = None  # "json", "form", "multipart"


class TechStackInfo(BaseModel):
    """Technology stack information extracted from documents."""

    languages: list[str] = []  # ["python", "javascript", "go"]
    frameworks: list[str] = []  # ["fastapi", "react", "gin"]
    databases: list[str] = []  # ["postgresql", "mongodb", "redis"]
    cloud_services: list[str] = []  # ["gcp-cloud-run", "aws-s3"]
    authentication: list[str] = []  # ["jwt", "oauth2", "session"]
    other: list[str] = []  # Any other relevant technologies


class ArchitectureInfo(BaseModel):
    """Architecture information extracted from documents."""

    components: list[Component] = []
    data_flows: list[DataFlow] = []
    entry_points: list[EntryPoint] = []
    authentication_type: str | None = None
    notes: str | None = None  # Additional architecture notes


class AppContext(BaseModel):
    """
    Complete application context for security testing.

    This is the primary data structure passed to exploit and remediation chains.
    It contains all information needed to understand and test the application.
    """

    # Basic info from user input
    app_name: str
    app_description: str
    app_url: str

    # Extracted from documents via Reducto
    tech_stack: TechStackInfo
    architecture: ArchitectureInfo

    # GCP Cloud Run container info
    gcp_project_id: str
    gcp_region: str
    gcp_service_name: str
    gcp_container_url: str  # The actual running URL

    # GitHub repository info
    github_org: str
    github_repo: str
    github_default_branch: str = "main"

    # Session info
    user_email: str
    session_id: str
    run_id: str | None = None

    def to_llm_context(self) -> str:
        """
        Format the context for inclusion in LLM prompts.

        Returns a structured string representation suitable for the LLM.
        """
        lines = [
            f"# Application: {self.app_name}",
            f"Description: {self.app_description}",
            f"URL: {self.app_url}",
            "",
            "## Technology Stack",
            f"Languages: {', '.join(self.tech_stack.languages)}",
            f"Frameworks: {', '.join(self.tech_stack.frameworks)}",
            f"Databases: {', '.join(self.tech_stack.databases)}",
            f"Authentication: {', '.join(self.tech_stack.authentication)}",
            "",
            "## Entry Points",
        ]

        for ep in self.architecture.entry_points:
            auth = "requires auth" if ep.authentication_required else "no auth"
            lines.append(f"- {ep.method} {ep.url} ({auth}): {ep.description}")

        lines.extend([
            "",
            "## Components",
        ])

        for comp in self.architecture.components:
            lines.append(f"- {comp.name} ({comp.type}): {comp.description}")

        return "\n".join(lines)
