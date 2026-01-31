"""
OpenRouter LLM provider implementation.

OpenRouter provides access to multiple LLM models through a unified API.
We use GLM-4.7 as the primary model with automatic fallback to other models.

API Reference: https://openrouter.ai/docs
"""

import re
from typing import AsyncIterator

import structlog
from openai import AsyncOpenAI
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ..config import Settings
from .base import BaseLLMProvider, LLMResponse

logger = structlog.get_logger(__name__)


class OpenRouterProvider(BaseLLMProvider):
    """
    OpenRouter LLM provider with GLM-4.7 as primary model.

    Features:
    - Automatic model fallback chain
    - Reasoning extraction from <think> tags
    - Retry with exponential backoff
    - Tool/function calling support
    """

    def __init__(self, settings: Settings):
        """
        Initialize the OpenRouter provider.

        Args:
            settings: Application settings with API key and configuration
        """
        self.settings = settings
        self.models = settings.OPENROUTER_MODELS
        self.client = AsyncOpenAI(
            api_key=settings.OPENROUTER_API_KEY,
            base_url=settings.OPENROUTER_BASE_URL,
            default_headers={
                "HTTP-Referer": settings.APP_URL,
                "X-Title": settings.APP_NAME,
            },
        )
        self._current_model_index = 0

    @property
    def current_model(self) -> str:
        """Get the current active model."""
        return self.models[self._current_model_index]

    def _extract_reasoning(self, content: str) -> tuple[str, str | None]:
        """
        Extract reasoning from <think> tags in GLM-4.7 responses.

        Args:
            content: The raw response content

        Returns:
            Tuple of (content_without_think_tags, extracted_reasoning)
        """
        think_pattern = r"<think>(.*?)</think>"
        matches = re.findall(think_pattern, content, re.DOTALL)

        if matches:
            reasoning = "\n".join(matches)
            clean_content = re.sub(think_pattern, "", content, flags=re.DOTALL).strip()
            return clean_content, reasoning

        return content, None

    @retry(
        retry=retry_if_exception_type(Exception),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
    )
    async def _call_api(
        self,
        messages: list[dict],
        temperature: float = 0.7,
        tools: list[dict] | None = None,
        stream: bool = False,
        model_override: str | None = None,
    ):
        """
        Make an API call with retry logic.

        Args:
            messages: Chat messages
            temperature: Sampling temperature
            tools: Optional tool definitions
            stream: Whether to stream the response
            model_override: Override the current model

        Returns:
            API response
        """
        model = model_override or self.current_model

        kwargs = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "stream": stream,
        }

        # Add reasoning effort for GLM-4.7
        if "glm-4.7" in model:
            kwargs["extra_body"] = {"reasoning": {"effort": "high"}}

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        logger.debug("calling_openrouter", model=model, stream=stream)

        try:
            response = await self.client.chat.completions.create(**kwargs)
            return response
        except Exception as e:
            logger.error("openrouter_api_error", model=model, error=str(e))
            raise

    async def _call_with_fallback(
        self,
        messages: list[dict],
        temperature: float = 0.7,
        tools: list[dict] | None = None,
    ) -> tuple:
        """
        Call API with automatic fallback through model chain.

        Returns:
            Tuple of (response, model_used)
        """
        last_error = None

        for i, model in enumerate(self.models):
            try:
                self._current_model_index = i
                response = await self._call_api(
                    messages=messages,
                    temperature=temperature,
                    tools=tools,
                    model_override=model,
                )
                logger.info("model_call_success", model=model)
                return response, model
            except Exception as e:
                logger.warning(
                    "model_fallback",
                    failed_model=model,
                    error=str(e),
                    next_model=self.models[i + 1] if i + 1 < len(self.models) else None,
                )
                last_error = e

        raise RuntimeError(f"All models failed. Last error: {last_error}")

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
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]

        response, model_used = await self._call_with_fallback(
            messages=messages,
            temperature=temperature,
        )

        content = response.choices[0].message.content or ""
        clean_content, reasoning = self._extract_reasoning(content)

        return LLMResponse(
            content=clean_content,
            model=model_used,
            reasoning=reasoning,
            usage={
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                "total_tokens": response.usage.total_tokens if response.usage else 0,
            },
        )

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
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]

        response, model_used = await self._call_with_fallback(
            messages=messages,
            temperature=temperature,
            tools=tools,
        )

        message = response.choices[0].message
        content = message.content or ""
        clean_content, reasoning = self._extract_reasoning(content)

        tool_calls = None
        if message.tool_calls:
            tool_calls = [
                {
                    "id": tc.id,
                    "type": tc.type,
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in message.tool_calls
            ]

        return LLMResponse(
            content=clean_content,
            model=model_used,
            reasoning=reasoning,
            tool_calls=tool_calls,
            usage={
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                "total_tokens": response.usage.total_tokens if response.usage else 0,
            },
        )

    async def stream_generate(
        self,
        prompt: str,
        system: str,
        temperature: float = 0.7,
    ) -> AsyncIterator[str]:
        """
        Stream a response from the LLM.

        Note: Streaming doesn't support automatic model fallback.

        Args:
            prompt: The user prompt
            system: The system prompt
            temperature: Sampling temperature

        Yields:
            Content chunks as they are generated
        """
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]

        response = await self._call_api(
            messages=messages,
            temperature=temperature,
            stream=True,
        )

        async for chunk in response:
            if chunk.choices and chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    async def generate_json(
        self,
        prompt: str,
        system: str,
        temperature: float = 0.3,
    ) -> LLMResponse:
        """
        Generate a JSON response from the LLM.

        Uses lower temperature for more deterministic JSON output.

        Args:
            prompt: The user prompt (should ask for JSON)
            system: The system prompt
            temperature: Sampling temperature (default 0.3 for JSON)

        Returns:
            LLMResponse with JSON content
        """
        # Add JSON instruction to system prompt if not present
        if "json" not in system.lower():
            system = f"{system}\n\nYou must respond with valid JSON only."

        return await self.generate(
            prompt=prompt,
            system=system,
            temperature=temperature,
        )

    async def generate_with_history(
        self,
        messages: list[dict],
        system: str,
        temperature: float = 0.7,
    ) -> LLMResponse:
        """
        Generate a response with conversation history.

        Args:
            messages: List of previous messages in OpenAI format
            system: The system prompt
            temperature: Sampling temperature

        Returns:
            LLMResponse with content and metadata
        """
        full_messages = [{"role": "system", "content": system}] + messages

        response, model_used = await self._call_with_fallback(
            messages=full_messages,
            temperature=temperature,
        )

        content = response.choices[0].message.content or ""
        clean_content, reasoning = self._extract_reasoning(content)

        return LLMResponse(
            content=clean_content,
            model=model_used,
            reasoning=reasoning,
            usage={
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                "total_tokens": response.usage.total_tokens if response.usage else 0,
            },
        )
