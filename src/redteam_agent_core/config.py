"""Configuration for RedTeam Agent Core"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Configuration settings loaded from environment variables.

    Required environment variables:
    - OPENROUTER_API_KEY: API key for OpenRouter
    - REDUCTO_API_KEY: API key for Reducto document processing
    - FIRECRAWL_API_KEY: API key for Firecrawl web crawling
    """

    # OpenRouter Configuration
    OPENROUTER_API_KEY: str
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"

    # Model priority list - will try in order if one fails
    OPENROUTER_MODELS: list[str] = [
        "z-ai/glm-4.7",                      # Primary - agent tasks, reasoning
        "deepseek/deepseek-r1",              # Fallback 1 - strong reasoning
        "anthropic/claude-3.5-sonnet",       # Fallback 2 - excellent code
        "google/gemini-2.0-flash-001",       # Fallback 3 - fast, cheap
    ]

    # App identification for OpenRouter headers
    APP_NAME: str = "redteam-agent"
    APP_URL: str = "https://github.com/redteam-agent"

    # Reducto Configuration
    REDUCTO_API_KEY: str
    REDUCTO_BASE_URL: str = "https://api.reducto.ai"

    # Firecrawl Configuration
    FIRECRAWL_API_KEY: str
    FIRECRAWL_BASE_URL: str = "https://api.firecrawl.dev"

    # Executor Service Configuration
    EXECUTOR_SERVICE_URL: str = "http://localhost:8001"
    EXECUTOR_TIMEOUT: int = 30  # seconds

    # Chain Configuration
    MAX_EXPLOIT_STEPS: int = 30
    MAX_REMEDIATION_ATTEMPTS: int = 5

    # Caching
    CACHE_TTL_HOURS: int = 24
    CACHE_DIR: str = ".cache"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
