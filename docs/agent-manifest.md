# Agent manifests

An agent manifest is a YAML file that declares what your agents are allowed to do: their prompts, their tools, and each tool's permissions and authentication. AgentLatch audits it alongside your source code, catching risky configuration before the agent runs.

```sh
agent-latch scan --config agent-manifest.yaml
```

If the scan target directory contains a file named `agent-manifest.yaml` (or `.yml`), it is used automatically, so `agent-latch scan` is enough. Only the top level of the target is checked: for a manifest in a subfolder, scan that folder or pass `--config path/to/agent-manifest.yaml`. One manifest is audited per scan.

## Example

```yaml
version: 1

agents:
  - name: ops-assistant
    system_prompt: |
      You are an operations assistant for the infrastructure team.
    prompt_templates:
      - prompts/ticket-summary.md
    tools: [run_shell, crm_lookup]

  - name: billing-agent
    system_prompt_file: prompts/billing-system.md
    tools:
      - name: issue_refund              # tools can also be declared inline
        capabilities: [payments:write]
        requires_approval: true
        endpoint: https://billing.example/api/refunds
        auth: oauth2

tools:
  - name: run_shell
    description: Execute shell commands on the host.
    capabilities: [shell]
    requires_approval: true

  - name: crm_lookup
    capabilities: [crm:read]
    endpoint: https://crm.example/api/v1
    auth: api_key
```

A deliberately insecure version is in [examples/vulnerable-agent](../examples/vulnerable-agent).

## Reference

### Agents (`agents:`)

| Field | Type | Checked for |
|---|---|---|
| `name` | string | Used in finding messages. |
| `system_prompt` | string | Injection phrases (`PRM001`) and user-input placeholders (`PRM002`). |
| `prompt` | string | Injection phrases (`PRM001`). |
| `system_prompt_file`, `system_prompt_template` | path | File contents get the same checks as `system_prompt`. |
| `prompt_templates`, `prompt_template`, `prompt_files` | path or list of paths | Injection phrases (`PRM001`) and secrets (`SEC001`). |
| `tools` | list of names or tool objects | Inline tool objects are checked like top-level tools. |

Prompt file paths are resolved relative to the manifest. A referenced file that cannot be read is reported as `MAN000` (info) so missing coverage is visible.

### Tools (`tools:`)

| Field | Type | Checked for |
|---|---|---|
| `name` | string | Used in finding messages. |
| `capabilities`, `permissions`, or `scopes` | list | High-risk capabilities (`MAN001`) and wildcards (`MAN002`). |
| `requires_approval`, `human_in_the_loop`, or `require_confirmation` | boolean | A true value satisfies `MAN001`. |
| `endpoint`, `url`, `base_url`, or `server` | string | Marks the tool as remote, enabling the `MAN003` auth check. |
| `auth` | string | `none`, `false`, `anonymous`, `no`, `off`, or empty triggers `MAN003`; missing triggers it with low confidence. |

High-risk capability names: `shell`, `exec`, `code_exec`, `code_execution`, `python`, `subprocess`, `filesystem:write`, `fs:write`, `file_write`, `filesystem:delete`, `database:write`, `db:write`, `email:send`, `payments`, `payments:write`, `sudo`, `admin`.

Wildcards: `*`, `all`, `any`, or anything ending in `:*`.

## Rules

| Rule | Severity | Triggered by | Fix |
|---|---|---|---|
| `MAN001` | high | High-risk capability without an approval flag | Require human approval, or narrow the capability. |
| `MAN002` | high | Wildcard permissions | List only the actions the tool needs. |
| `MAN003` | medium | Remote endpoint with missing or disabled auth | Authenticate the tool with a credential scoped to it. |
| `PRM001` | medium | Phrases like "ignore all previous instructions" in a prompt | Find where the text came from; never paste untrusted content into templates. |
| `PRM002` | medium | `{user_input}`, `{{ query }}`, `${message}` inside a system prompt | Pass user input in the user turn, delimited and labelled as data. |
| `MAN000` | info | Referenced prompt file not found | Fix the path. Does not affect `--fail-on`. |

Full detection details and blind spots are in [RULES.md](RULES.md).

## Limits

The manifest describes intended configuration. AgentLatch does not verify that your code enforces it, so a manifest that says `requires_approval: true` passes even if the code never asks. Keep the manifest next to the code it describes and review both together.
