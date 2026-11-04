# ALR04 unit-test payloads (synthetic)

Every payload in this folder is **synthetic**. None of it is taken from a real MCP server, a
real credential is referenced (paths such as `~/.ssh/id_rsa` are names only), and each URL uses
the reserved `example` domain. The files exist to give the ALR04 test suite a labelled corpus:
the outcome below is declared **before** the gate runs, and `tests/test_alr04.py` compares it
with what the gate actually returns.

JSON has no docstrings, so every file carries a `_synthetic` field that plays that role.

| Folder | Category | Declared outcome |
|---|---|---|
| `vulnerable/` | `vulnerable_baseline`, `vulnerable_obfuscated` | `FAIL` (blocks at `--fail-on high`) |
| `safe/` | `safe_standard`, `safe_trap` | `PASS` (one declared `known_false_positive` blocks) |

Fields:

- `_synthetic`: the docstring, stating that the payload is synthetic.
- `id`, `category`: stable names for the report.
- `expected_outcome`: the exact worst outcome the gate must return for this payload.
- `expected_rules`: rule IDs that must appear among the findings (a subset check).
- `server`, `tools`: the `tools/list` response the gate is fed.

A payload that looks dangerous but is safe on purpose is a **false-positive trap**: the gate
should not block it. One trap, `safe/trap_quoted_attack.json`, blocks today: the framing sentence
("Rejects prompt-injection input.") and the quoted attack are separate clauses, so the example
marker cannot soften the quoted clause. It stays in the corpus on purpose, declares
`known_false_positive: true`, and is counted as a false positive by the metrics, so the score
reports the gate's real precision instead of hiding the case.

Similarly, `vulnerable/obfuscated_html_comment.json` blocks on `ALR04-003` (concealment) rather
than `ALR04-007` (hidden transport): the comment text is part of the visible description, so the
match is attributed to the visible layer. The block decision is unaffected; only the rule
attribution differs from what the module docstring implies for comments.
