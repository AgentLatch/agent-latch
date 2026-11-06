"""Deliberately insecure OpenAI Agents SDK project for AgentLatch demos and tests. Do not deploy.

A triage agent hands off to a billing agent. Billing can issue refunds over HTTP with no human
approval, triage's instructions are built from user input, the run allows 500 turns, a remote MCP
server is reached over plain http://, and an input guardrail is written but never attached.
"""

from __future__ import annotations

import requests
from agents import (
    Agent,
    GuardrailFunctionOutput,
    Runner,
    function_tool,
    handoff,
    input_guardrail,
)
from agents.mcp import MCPServerStreamableHttp

BILLING_API = "https://billing.example.com"


@function_tool
def lookup_order(order_id: str) -> str:
    """Look up an order's status."""
    return requests.get(f"{BILLING_API}/orders/{order_id}", timeout=10).text


@function_tool
def issue_refund(order_id: str, amount: float) -> str:
    """Refund an order. Runs as soon as the model asks: there is no approval step."""
    response = requests.post(
        f"{BILLING_API}/refunds", json={"order_id": order_id, "amount": amount}, timeout=10
    )
    return response.text


@input_guardrail
async def block_refund_abuse(ctx, agent, user_input):
    """Meant to stop "refund everything" requests, but no agent below uses it."""
    flagged = "refund all" in str(user_input).lower()
    return GuardrailFunctionOutput(output_info=None, tripwire_triggered=flagged)


# Remote tool server over plaintext HTTP: anyone on the network path can read or change the traffic.
crm_tools = MCPServerStreamableHttp(params={"url": "http://crm-tools.example.com/mcp"})

billing_agent = Agent(
    name="billing",
    instructions="You handle refunds and order questions.",
    tools=[lookup_order, issue_refund],
    mcp_servers=[crm_tools],
)


def build_triage(customer_name: str, customer_message: str) -> Agent:
    return Agent(
        name="triage",
        # User text becomes part of the system-level instructions.
        instructions=f"You are triage for {customer_name}. Their request: {customer_message}",
        tools=[lookup_order],
        handoffs=[handoff(billing_agent)],
    )


async def answer(customer_name: str, customer_message: str) -> str:
    triage = build_triage(customer_name, customer_message)
    async with crm_tools:
        result = await Runner.run(triage, customer_message, max_turns=500)
    return result.final_output
