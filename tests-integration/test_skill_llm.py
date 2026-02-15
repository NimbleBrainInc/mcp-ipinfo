"""
Smoke test: verify the LLM reads the skill resource and selects the correct tool.

Requires ANTHROPIC_API_KEY and IPINFO_API_TOKEN in environment.
"""

import os

import anthropic
import pytest
from fastmcp import Client

from mcp_ipinfo.server import mcp


def get_anthropic_client() -> anthropic.Anthropic:
    token = os.environ.get("ANTHROPIC_API_KEY")
    if not token:
        pytest.skip("ANTHROPIC_API_KEY not set")
    return anthropic.Anthropic(api_key=token)


async def get_server_context() -> dict:
    """Extract instructions, skill content, and tool definitions from the MCP server."""
    async with Client(mcp) as client:
        init = await client.initialize()
        instructions = init.instructions

        resources = await client.list_resources()
        skill_text = ""
        for r in resources:
            if "skill://" in str(r.uri):
                contents = await client.read_resource(str(r.uri))
                skill_text = contents[0].text if hasattr(contents[0], "text") else str(contents[0])

        tools_list = await client.list_tools()
        tools = []
        for t in tools_list:
            tool_def = {
                "name": t.name,
                "description": t.description or "",
                "input_schema": t.inputSchema,
            }
            tools.append(tool_def)

        return {
            "instructions": instructions,
            "skill": skill_text,
            "tools": tools,
        }


def build_messages(system: str, user_prompt: str) -> tuple[str, list[dict]]:
    return system, [{"role": "user", "content": user_prompt}]


class TestSkillLLMInvocation:
    """Test that an LLM reads the skill and makes correct tool choices."""

    @pytest.mark.asyncio
    async def test_vpn_query_selects_plus_api(self):
        """When asked 'is this IP a VPN?', the LLM should call get_plus_ip_info, not get_ip_info.

        The skill explicitly teaches: use get_plus_ip_info for VPN/proxy/Tor detection.
        If the model calls get_ip_info instead, it didn't follow the skill.
        """
        ctx = await get_server_context()
        client = get_anthropic_client()

        system = (
            f"You are an IP intelligence assistant.\n\n"
            f"## Server Instructions\n{ctx['instructions']}\n\n"
            f"## Skill Resource\n{ctx['skill']}"
        )

        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": "Is 8.8.8.8 a VPN?"}],
            tools=[{"type": "custom", **t} for t in ctx["tools"]],
        )

        # Find the tool_use block
        tool_calls = [b for b in response.content if b.type == "tool_use"]
        assert len(tool_calls) > 0, "LLM did not call any tool"

        tool_name = tool_calls[0].name
        assert tool_name == "get_plus_ip_info", (
            f"LLM called {tool_name} instead of get_plus_ip_info. "
            "Skill instructs: use get_plus_ip_info for VPN detection."
        )
        assert tool_calls[0].input.get("ip") == "8.8.8.8"

    @pytest.mark.asyncio
    async def test_general_lookup_selects_get_ip_info(self):
        """A general 'lookup this IP' query should call get_ip_info, not the Plus API."""
        ctx = await get_server_context()
        client = get_anthropic_client()

        system = (
            f"You are an IP intelligence assistant.\n\n"
            f"## Server Instructions\n{ctx['instructions']}\n\n"
            f"## Skill Resource\n{ctx['skill']}"
        )

        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": "Look up 1.1.1.1"}],
            tools=[{"type": "custom", **t} for t in ctx["tools"]],
        )

        tool_calls = [b for b in response.content if b.type == "tool_use"]
        assert len(tool_calls) > 0, "LLM did not call any tool"

        tool_name = tool_calls[0].name
        assert tool_name == "get_ip_info", (
            f"LLM called {tool_name} instead of get_ip_info. "
            "Skill instructs: use get_ip_info for general lookups."
        )
        assert tool_calls[0].input.get("ip") == "1.1.1.1"

    @pytest.mark.asyncio
    async def test_without_skill_may_choose_wrong_tool(self):
        """Without the skill, the LLM is more likely to pick the wrong tool for VPN queries.

        This is the control test. We don't assert failure (the model might still guess right),
        but we log the result for comparison.
        """
        ctx = await get_server_context()
        client = get_anthropic_client()

        # No skill content, just bare instructions
        system = "You are an IP intelligence assistant."

        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": "Is 8.8.8.8 a VPN?"}],
            tools=[{"type": "custom", **t} for t in ctx["tools"]],
        )

        tool_calls = [b for b in response.content if b.type == "tool_use"]
        if tool_calls:
            tool_name = tool_calls[0].name
            used_correct = tool_name == "get_plus_ip_info"
            print(f"\n  Without skill: LLM called {tool_name} (correct={used_correct})")
        else:
            print("\n  Without skill: LLM did not call any tool")
