"""Base LLM provider interface."""

from abc import ABC, abstractmethod
from typing import AsyncIterator

from pydantic import BaseModel


class LLMResponse(BaseModel):
    """Response from an LLM provider."""

    content: str
    model: str
    reasoning: str | None = None  # Extracted from <think> tags
    tool_calls: list[dict] | None = None
    usage: dict = {}


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system: str,
        temperature: float = 0.7,
    ) -> LLMResponse:
        """
        Generate a response from the LLM.

        Args:
            prompt: The user prompt
            system: The system prompt
            temperature: Sampling temperature (0-1)

        Returns:
            LLMResponse with content and metadata
        """
        ...

    @abstractmethod
    async def generate_with_tools(
        self,
        prompt: str,
        tools: list[dict],
        system: str,
        temperature: float = 0.7,
    ) -> LLMResponse:
        """
        Generate a response with tool/function calling.

        Args:
            prompt: The user prompt
            tools: List of tool definitions (OpenAI format)
            system: The system prompt
            temperature: Sampling temperature

        Returns:
            LLMResponse with optional tool_calls
        """
        ...

    @abstractmethod
    async def stream_generate(
        self,
        prompt: str,
        system: str,
        temperature: float = 0.7,
    ) -> AsyncIterator[str]:
        """
        Stream a response from the LLM.

        Args:
            prompt: The user prompt
            system: The system prompt
            temperature: Sampling temperature

        Yields:
            Content chunks as they are generated
        """
        ...
