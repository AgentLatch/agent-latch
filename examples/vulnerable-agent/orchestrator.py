"""Deliberately insecure multi-agent orchestration for AgentLatch demos. Do not deploy."""

from autogen import AssistantAgent, UserProxyAgent
from langchain.agents import AgentExecutor
from langchain_core.tools import tool


@tool
def write_report(path: str, text: str) -> str:
    """Save a report for the user."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


def build_executor(agent, tools):
    # No step limit: one bad plan can loop and call tools forever.
    return AgentExecutor(agent=agent, tools=[*tools, write_report], max_iterations=None)


def build_coding_team(llm_config):
    assistant = AssistantAgent("coder", llm_config=llm_config)
    # Runs model-written code on the host without ever asking a human.
    runner = UserProxyAgent(
        "runner",
        human_input_mode="NEVER",
        code_execution_config={"work_dir": "workspace", "use_docker": False},
    )
    return assistant, runner
