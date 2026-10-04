# Contributing

Thanks for helping improve AgentLatch. This is an early proof of concept; keep changes small, explain limitations, and avoid overstating detection coverage.

## Development

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev,audit]"
python -m pytest
ruff check .
ruff format --check .        # `ruff format .` to fix
pip-audit --skip-editable
```

Markdown, YAML, and JSON are formatted with Prettier, and any JavaScript is linted with ESLint (Node.js 24):

```sh
npm ci
npm run format:check         # `npm run format` to fix
npm run lint
npm audit
```

CI runs each of these as a separate check: the **Code quality (Python)** and **Code quality (Node)** workflows.

## Adding a rule

Where rules live:

| Kind of rule | File |
| --- | --- |
| Python source patterns (`PY*`, `AG001`, `AG002`) and secrets (`SEC001`) | `src/agent_latch/rules.py` |
| Data flow into prompts (`AG003`) | `src/agent_latch/taint.py` |
| Agent manifests and prompt templates (`MAN*`, `PRM*`) | `src/agent_latch/manifest.py` |
| Suppressions (`.agent-latch-ignore`, inline ignores) | `src/agent_latch/suppress.py` |

- Give it a stable unique ID and a focused title.
- Add a safe fixture that demonstrates the detection and, where relevant, a non-finding fixture.
- Include severity, confidence, concise evidence, remediation guidance, and a relevant OWASP mapping only when justified.
- Never include detected secret values in evidence or reports.
- State clearly whether the check is heuristic, static, or runtime-tested.
- Document the rule in `docs/RULES.md` (detection and blind spots) and in the README rule table.
- If the demo project should show it, extend `examples/vulnerable-agent` and its README.

## Pull requests

Include the risk addressed, test evidence, limitations, and any behavior or output-format changes. Do not submit real secrets or sensitive code samples.
