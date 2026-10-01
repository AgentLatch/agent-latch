# Vulnerable agent example

A deliberately insecure agent project for demos and tests. **Do not deploy or copy this code.**

## Run it

From the repository root, with AgentLatch installed:

```sh
cd examples/vulnerable-agent
agent-latch scan --config agent-manifest.yaml
```

## Expected findings

| Severity | Rule | Where | Problem |
|---|---|---|---|
| HIGH | `MAN001` | `agent-manifest.yaml` | `run_shell` can run shell commands with no approval step. |
| HIGH | `MAN002` | `agent-manifest.yaml` | `file_manager` has wildcard (`*`) permissions. |
| HIGH | `PY002` | `tools.py` | `subprocess.run(..., shell=True)` allows command injection. |
| MEDIUM | `MAN003` | `agent-manifest.yaml` | `crm_lookup` calls a remote endpoint with `auth: none`. |
| MEDIUM | `PRM002` | `agent-manifest.yaml` | `{user_input}` is placed inside the system prompt. |
| MEDIUM | `PRM002` | `prompts/billing-system.md` | `{{ customer_message }}` is placed inside the system prompt. |
| MEDIUM | `PRM001` | `prompts/ticket-summary.md` | The ticket text contains "Ignore all previous instructions". |
| MEDIUM | `AG003` | `tools.py` | A fetched web page goes straight into the LLM message. |

`agent-latch scan --config agent-manifest.yaml --fail-on high` exits with code 1, which is how CI would block this project.

## Files

| File | Contents |
|---|---|
| `agent-manifest.yaml` | Two agents and their tools, with insecure permissions and auth. |
| `prompts/ticket-summary.md` | A prompt template carrying an injected instruction. |
| `prompts/billing-system.md` | A system prompt that interpolates user input. |
| `tools.py` | Tool code with `shell=True` and an unfenced web-to-prompt flow. |

The `billing-agent`'s `issue_refund` tool is configured safely (approval required, OAuth, HTTPS) and produces no findings, as a contrast.
