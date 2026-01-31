"""Tests for LLM providers."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from redteam_agent_core.config import Settings
from redteam_agent_core.llm import LLMResponse, OpenRouterProvider


@pytest.fixture
def mock_settings():
    """Create mock settings for testing."""
    settings = MagicMock(spec=Settings)
    settings.OPENROUTER_API_KEY = "test-api-key"
    settings.OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
    settings.OPENROUTER_MODELS = [
        "z-ai/glm-4.7",
        "deepseek/deepseek-r1",
        "anthropic/claude-3.5-sonnet",
    ]
    settings.APP_URL = "https://test.example.com"
    settings.APP_NAME = "test-app"
    return settings


class TestOpenRouterProvider:
    """Tests for OpenRouterProvider."""

    def test_init(self, mock_settings):
        """Test provider initialization."""
        with patch("redteam_agent_core.llm.openrouter.AsyncOpenAI"):
            provider = OpenRouterProvider(mock_settings)
            assert provider.current_model == "z-ai/glm-4.7"
            assert len(provider.models) == 3

    def test_extract_reasoning_with_think_tags(self, mock_settings):
        """Test extraction of reasoning from <think> tags."""
        with patch("redteam_agent_core.llm.openrouter.AsyncOpenAI"):
            provider = OpenRouterProvider(mock_settings)

            content = "<think>I need to analyze this carefully.</think>Here is my response."
            clean_content, reasoning = provider._extract_reasoning(content)

            assert clean_content == "Here is my response."
            assert reasoning == "I need to analyze this carefully."

    def test_extract_reasoning_multiple_tags(self, mock_settings):
        """Test extraction with multiple <think> tags."""
        with patch("redteam_agent_core.llm.openrouter.AsyncOpenAI"):
            provider = OpenRouterProvider(mock_settings)

            content = "<think>First thought.</think>Response one.<think>Second thought.</think>Response two."
            clean_content, reasoning = provider._extract_reasoning(content)

            assert clean_content == "Response one.Response two."
            assert "First thought." in reasoning
            assert "Second thought." in reasoning

    def test_extract_reasoning_no_tags(self, mock_settings):
        """Test extraction when no <think> tags present."""
        with patch("redteam_agent_core.llm.openrouter.AsyncOpenAI"):
            provider = OpenRouterProvider(mock_settings)

            content = "Just a normal response without thinking."
            clean_content, reasoning = provider._extract_reasoning(content)

            assert clean_content == content
            assert reasoning is None

    @pytest.mark.asyncio
    async def test_generate(self, mock_settings):
        """Test basic generation."""
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(
                message=MagicMock(content="Generated response", tool_calls=None)
            )
        ]
        mock_response.usage = MagicMock(
            prompt_tokens=10, completion_tokens=20, total_tokens=30
        )

        with patch("redteam_agent_core.llm.openrouter.AsyncOpenAI") as mock_client_class:
            mock_client = MagicMock()
            mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
            mock_client_class.return_value = mock_client

            provider = OpenRouterProvider(mock_settings)
            response = await provider.generate(
                prompt="Test prompt",
                system="You are a helpful assistant",
                temperature=0.7,
            )

            assert isinstance(response, LLMResponse)
            assert response.content == "Generated response"
            assert response.usage["total_tokens"] == 30

    @pytest.mark.asyncio
    async def test_generate_with_reasoning(self, mock_settings):
        """Test generation with reasoning extraction."""
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(
                message=MagicMock(
                    content="<think>Analyzing the request...</think>Here is my answer.",
                    tool_calls=None,
                )
            )
        ]
        mock_response.usage = MagicMock(
            prompt_tokens=10, completion_tokens=20, total_tokens=30
        )

        with patch("redteam_agent_core.llm.openrouter.AsyncOpenAI") as mock_client_class:
            mock_client = MagicMock()
            mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
            mock_client_class.return_value = mock_client

            provider = OpenRouterProvider(mock_settings)
            response = await provider.generate(
                prompt="Test prompt",
                system="You are a helpful assistant",
            )

            assert response.content == "Here is my answer."
            assert response.reasoning == "Analyzing the request..."

    @pytest.mark.asyncio
    async def test_generate_with_tools(self, mock_settings):
        """Test generation with tool calling."""
        mock_function = MagicMock()
        mock_function.name = "execute_command"
        mock_function.arguments = '{"command": "curl http://example.com"}'

        mock_tool_call = MagicMock()
        mock_tool_call.id = "call_123"
        mock_tool_call.type = "function"
        mock_tool_call.function = mock_function

        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(
                message=MagicMock(content="", tool_calls=[mock_tool_call])
            )
        ]
        mock_response.usage = MagicMock(
            prompt_tokens=10, completion_tokens=20, total_tokens=30
        )

        with patch("redteam_agent_core.llm.openrouter.AsyncOpenAI") as mock_client_class:
            mock_client = MagicMock()
            mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
            mock_client_class.return_value = mock_client

            provider = OpenRouterProvider(mock_settings)
            tools = [
                {
                    "type": "function",
                    "function": {
                        "name": "execute_command",
                        "description": "Execute a command",
                        "parameters": {"type": "object", "properties": {}},
                    },
                }
            ]
            response = await provider.generate_with_tools(
                prompt="Execute a curl command",
                tools=tools,
                system="You are a security tester",
            )

            assert response.tool_calls is not None
            assert len(response.tool_calls) == 1
            assert response.tool_calls[0]["function"]["name"] == "execute_command"

    @pytest.mark.asyncio
    async def test_fallback_on_error(self, mock_settings):
        """Test model fallback when primary model fails."""
        # The retry decorator retries 3 times before fallback
        # So we need to fail 3 times for the first model
        call_count = 0

        async def mock_create(**kwargs):
            nonlocal call_count
            call_count += 1
            model = kwargs.get("model", "")
            # Fail all calls to the primary model (glm-4.7)
            if "glm-4.7" in model:
                raise Exception("Primary model failed")
            # Succeed on fallback model
            mock_response = MagicMock()
            mock_response.choices = [
                MagicMock(message=MagicMock(content="Fallback response", tool_calls=None))
            ]
            mock_response.usage = MagicMock(
                prompt_tokens=10, completion_tokens=20, total_tokens=30
            )
            return mock_response

        with patch("redteam_agent_core.llm.openrouter.AsyncOpenAI") as mock_client_class:
            mock_client = MagicMock()
            mock_client.chat.completions.create = mock_create
            mock_client_class.return_value = mock_client

            provider = OpenRouterProvider(mock_settings)
            response = await provider.generate(
                prompt="Test prompt",
                system="System prompt",
            )

            assert response.content == "Fallback response"
            assert response.model == "deepseek/deepseek-r1"

    @pytest.mark.asyncio
    async def test_all_models_fail(self, mock_settings):
        """Test error when all models fail."""
        with patch("redteam_agent_core.llm.openrouter.AsyncOpenAI") as mock_client_class:
            mock_client = MagicMock()
            mock_client.chat.completions.create = AsyncMock(
                side_effect=Exception("All models failed")
            )
            mock_client_class.return_value = mock_client

            provider = OpenRouterProvider(mock_settings)

            with pytest.raises(RuntimeError, match="All models failed"):
                await provider.generate(
                    prompt="Test prompt",
                    system="System prompt",
                )


class TestLLMResponse:
    """Tests for LLMResponse model."""

    def test_basic_response(self):
        """Test basic LLMResponse creation."""
        response = LLMResponse(
            content="Test content",
            model="z-ai/glm-4.7",
        )
        assert response.content == "Test content"
        assert response.model == "z-ai/glm-4.7"
        assert response.reasoning is None
        assert response.tool_calls is None
        assert response.usage == {}

    def test_response_with_reasoning(self):
        """Test LLMResponse with reasoning."""
        response = LLMResponse(
            content="Response content",
            model="z-ai/glm-4.7",
            reasoning="Step by step thinking",
            usage={"total_tokens": 100},
        )
        assert response.reasoning == "Step by step thinking"
        assert response.usage["total_tokens"] == 100
