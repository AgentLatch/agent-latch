"""Deliberately insecure tool implementations for AgentLatch demos. Do not deploy."""

import subprocess

import requests
from langchain_core.messages import HumanMessage, SystemMessage


def run_shell(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True, check=False).stdout


def fetch_page(url: str) -> str:
    return requests.get(url, timeout=10).text


def summarize_page(llm, url: str) -> str:
    page = fetch_page(url)
    messages = [
        SystemMessage(content="Summarize the page for the user."),
        HumanMessage(content=f"Page content:\n{page}"),
    ]
    return llm.invoke(messages).content
