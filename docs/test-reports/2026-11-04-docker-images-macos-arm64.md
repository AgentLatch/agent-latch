# AgentLatch Docker images: test report

Started: 2026-11-04 21:54:55 GMT (UTC+0000)  
Finished: 2026-11-04 21:55:17 GMT (UTC+0000)

Every output below is the real, unedited combined stdout and stderr of the command, run with bash from the root of the agent-latch repository (so `$PWD` is the repo). PASS or FAIL comes from the fixed rule printed with each check.

## 1. Environment

Container engine: **Docker Desktop** (from `docker info` and `docker context show` below).

```text
$ sw_vers
ProductName:		macOS
ProductVersion:		26.6.2
BuildVersion:		25G83
[exit code 0]
$ uname -m
arm64
[exit code 0]
$ sysctl -n machdep.cpu.brand_string
Apple M1 Pro
[exit code 0]
$ docker version --format 'Client: {{.Client.Version}}  Server: {{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}})'
Client: 29.9.2  Server: 29.9.2 (linux/arm64)
[exit code 0]
$ docker info --format 'OperatingSystem: {{.OperatingSystem}}'
OperatingSystem: Docker Desktop
[exit code 0]
$ docker context show
desktop-linux
[exit code 0]
```

## 2. What was tested

| Item | Value |
|---|---|
| Branch | `claude/relaxed-carson-hodmui` |
| Commit | `6be6bf6b5457a99366d9b75b725772fc4a9ff2a9` |

| Image | Image ID | Size | Architecture |
|---|---|---|---|
| `agent-latch:test` | `sha256:fe6cbffc2eaf14d0595f918fef03465880bdd277fd41881cc22e045d2c865b9b` | 269,853,173 bytes (269.9 MB) | arm64 |
| `agent-latch-runtime:test` | `sha256:55ee8779979f69bfd3c5068e32d858386543111953cd43b4b112df4c27bd7f6d` | 340,738,451 bytes (340.7 MB) | arm64 |

Source of the table:

```text
$ docker image inspect --format '{{.Id}} {{.Size}} {{.Architecture}}' agent-latch:test
sha256:fe6cbffc2eaf14d0595f918fef03465880bdd277fd41881cc22e045d2c865b9b 269853173 arm64
[exit code 0]
$ docker image inspect --format '{{.Id}} {{.Size}} {{.Architecture}}' agent-latch-runtime:test
sha256:55ee8779979f69bfd3c5068e32d858386543111953cd43b4b112df4c27bd7f6d 340738451 arm64
[exit code 0]
```

## 3. Summary

| # | Check | Expected | Actual | Result |
|---|---|---|---|---|
| 1 | Scanner image architecture | arm64 | arm64 | **PASS** |
| 2 | Scanner version | agent-latch 0.5.0 | agent-latch 0.5.0 | **PASS** |
| 3 | Scanner runs as non-root | 10001 | 10001 | **PASS** |
| 4 | Scanner has no Node.js, compiler or git | none | none | **PASS** |
| 5 | Scan of demo project (read-only mount) | HIGH findings, exit code 1 | exit 1, 4 HIGH finding(s): MAN001, MAN002, AG006, PY002 | **PASS** |
| 6 | Project mount is read-only | "Read-only file system", non-zero exit | exit 1: touch: cannot touch '/src/x': Read-only file system | **PASS** |
| 7 | SARIF report | exit 0, 12 results in the SARIF | exit 0, 12 result(s) in SARIF | **PASS** |
| 8 | Configuration error exit code | exit code 2 | exit 2: agent-latch [scan] [path] [options] | **PASS** |
| 9 | Runtime image: architecture, version, non-root, no Node.js/compiler | arm64 / agent-latch-runtime 0.5.0 / 10001 / none | arm64 / agent-latch-runtime 0.5.0 / 10001 / none | **PASS** |
| 10 | Runtime demo | about ten event lines, then the list of files written | exit 0, 10 event lines, files in runtime-logs/demo: trace.jsonl, payloads.jsonl, events.csv, gate-results.csv, normalized.jsonl, proxy.log | **PASS** |
| 11 | Log files are private | -rw------- on the log files | 6 file(s); not private: proxy.log | **FAIL** |
| 12 | Real MCP over stdio (docker run -i) | server "weather", 4 tools, weather reply for Paris, container exit 0, every stdout line is JSON | server "weather", 4 tools, reply "Weather in Paris: 18 degrees (metric), light rain.", container exit 0, all stdout JSON: True | **PASS** |
| 13 | Ledger intact | AUDIT TRAIL UNANCHORED, exit 0 | exit 0: AUDIT TRAIL UNANCHORED — 3 record(s) verify locally, but nothing outside the machine proves the file was not rebuilt. | **PASS** |
| 14 | Ledger catches tampering (line 2 of /data/t.jsonl deleted) | AUDIT TRAIL DELETED, exit 1 | exit 1: AUDIT TRAIL DELETED — records are missing; the log cannot be trusted. | **PASS** |
| 15 | HTTP safety lock | "--http must use a loopback address", exit 2 | exit 2: agent-latch-runtime: --http must use a loopback address such as 127.0.0.1 | **PASS** |
| 16 | Clean shutdown on docker stop | stop under 2 seconds, exit code 0 | status before stop: running; stop took 0.13 s; container exit code 0 | **PASS** |

**15 of 16 checks passed**

## 4. Details

### Setup: build both images

Command:

```bash
docker build --target scanner -t agent-latch:test .
```

Output (full, unedited):

```text
#0 building with "desktop-linux" instance using docker driver

#1 [internal] load build definition from Dockerfile
#1 transferring dockerfile: 3.51kB done
#1 DONE 0.0s

#2 resolve image config for docker-image://docker.io/docker/dockerfile:1
#2 ...

#3 [auth] docker/dockerfile:pull token for registry-1.docker.io
#3 DONE 0.0s

#2 resolve image config for docker-image://docker.io/docker/dockerfile:1
#2 DONE 0.9s

#4 docker-image://docker.io/docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#4 resolve docker.io/docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e done
#4 CACHED

#5 [internal] load metadata for docker.io/library/python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1
#5 ...

#6 [auth] library/python:pull token for registry-1.docker.io
#6 DONE 0.0s

#5 [internal] load metadata for docker.io/library/python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1
#5 DONE 0.8s

#7 [internal] load .dockerignore
#7 transferring context: 318B done
#7 DONE 0.0s

#8 [build 1/5] FROM docker.io/library/python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1
#8 resolve docker.io/library/python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1 done
#8 DONE 0.0s

#9 [internal] load build context
#9 transferring context: 43.49kB 0.0s done
#9 DONE 0.0s

#10 [base 2/2] RUN groupadd --gid 10001 latch  && useradd --uid 10001 --gid latch --no-create-home --home-dir /nonexistent       --shell /usr/sbin/nologin latch
#10 CACHED

#11 [build 2/5] WORKDIR /build
#11 CACHED

#12 [scanner 2/3] RUN --mount=type=bind,from=build,source=/wheels,target=/wheels     pip install --require-hashes --only-binary=:all: -r /tmp/requirements.txt  && pip install --no-deps --no-index /wheels/*.whl  && rm /tmp/requirements.txt
#12 CACHED

#13 [build 3/5] COPY pyproject.toml README.md LICENSE ./
#13 CACHED

#14 [scanner 1/3] COPY docker/requirements-scanner.txt /tmp/requirements.txt
#14 CACHED

#15 [build 4/5] COPY src ./src
#15 CACHED

#16 [build 5/5] RUN pip wheel --no-deps --wheel-dir /wheels .
#16 CACHED

#17 [scanner 3/3] WORKDIR /src
#17 CACHED

#18 exporting to image
#18 exporting layers done
#18 exporting manifest sha256:2eb2054f0b854a94fa4fa8f791fa60845f7dc4790c72ae554dc070bd9c0282e1 done
#18 exporting config sha256:102845873530c81326df534610fc619460de36a9626e03c3659536b140503ced done
#18 exporting attestation manifest sha256:3078a38d98385a4abe7575e178f55981adb92299df959a74bbb553d74aae733e done
#18 exporting manifest list sha256:fe6cbffc2eaf14d0595f918fef03465880bdd277fd41881cc22e045d2c865b9b done
#18 naming to docker.io/library/agent-latch:test done
#18 unpacking to docker.io/library/agent-latch:test done
#18 DONE 0.0s
```

Exit code: `0`

Command:

```bash
docker build --target runtime -t agent-latch-runtime:test .
```

Output (full, unedited):

```text
#0 building with "desktop-linux" instance using docker driver

#1 [internal] load build definition from Dockerfile
#1 transferring dockerfile: 3.51kB done
#1 DONE 0.0s

#2 resolve image config for docker-image://docker.io/docker/dockerfile:1
#2 DONE 0.3s

#3 docker-image://docker.io/docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#3 resolve docker.io/docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e 0.0s done
#3 CACHED

#4 [internal] load metadata for docker.io/library/python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1
#4 DONE 0.0s

#5 [internal] load .dockerignore
#5 transferring context: 318B done
#5 DONE 0.0s

#6 [internal] load build context
#6 DONE 0.0s

#7 [build 1/5] FROM docker.io/library/python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1
#7 resolve docker.io/library/python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1 done
#7 DONE 0.0s

#6 [internal] load build context
#6 transferring context: 81.00kB 0.0s done
#6 DONE 0.0s

#8 [runtime 1/3] COPY docker/requirements-runtime.txt /tmp/requirements.txt
#8 CACHED

#9 [build 2/5] WORKDIR /build
#9 CACHED

#10 [build 3/5] COPY pyproject.toml README.md LICENSE ./
#10 CACHED

#11 [base 2/2] RUN groupadd --gid 10001 latch  && useradd --uid 10001 --gid latch --no-create-home --home-dir /nonexistent       --shell /usr/sbin/nologin latch
#11 CACHED

#12 [build 5/5] RUN pip wheel --no-deps --wheel-dir /wheels .
#12 CACHED

#13 [build 4/5] COPY src ./src
#13 CACHED

#14 [runtime 2/3] RUN --mount=type=bind,from=build,source=/wheels,target=/wheels     pip install --require-hashes --only-binary=:all: -r /tmp/requirements.txt  && pip install --no-deps --no-index /wheels/*.whl  && rm /tmp/requirements.txt  && mkdir /data && chown 10001:10001 /data
#14 CACHED

#15 [runtime 3/3] WORKDIR /data
#15 CACHED

#16 exporting to image
#16 exporting layers done
#16 exporting manifest sha256:8480e76d3edcd7768932a6821af750b121adb4399f0ccecfcc21fa34a938d98c done
#16 exporting config sha256:beb3fcd82d01c8bff695248404bc1d565f37aaab3c3f2c4a7a9990daeac22759 done
#16 exporting attestation manifest sha256:deb7ce97fa4147024631ae6262276605f4cd125b81b223e8591ec909982b3362 done
#16 exporting manifest list sha256:55ee8779979f69bfd3c5068e32d858386543111953cd43b4b112df4c27bd7f6d done
#16 naming to docker.io/library/agent-latch-runtime:test done
#16 unpacking to docker.io/library/agent-latch-runtime:test done
#16 DONE 0.0s
```

Exit code: `0`

### Check 1: Scanner image architecture — PASS

Expected: arm64  
PASS rule: exit 0 and output is exactly arm64  
Actual: arm64

Command:

```bash
docker image inspect agent-latch:test --format '{{.Architecture}}'
```

Output (full, unedited):

```text
arm64
```

Exit code: `0`

### Check 2: Scanner version — PASS

Expected: agent-latch 0.5.0  
PASS rule: exit 0 and output is exactly agent-latch 0.5.0  
Actual: agent-latch 0.5.0

Command:

```bash
docker run --rm agent-latch:test --version
```

Output (full, unedited):

```text
agent-latch 0.5.0
```

Exit code: `0`

### Check 3: Scanner runs as non-root — PASS

Expected: 10001  
PASS rule: exit 0 and output is exactly 10001  
Actual: 10001

Command:

```bash
docker run --rm --entrypoint id agent-latch:test -u
```

Output (full, unedited):

```text
10001
```

Exit code: `0`

### Check 4: Scanner has no Node.js, compiler or git — PASS

Expected: none  
PASS rule: output is exactly none (no tool path printed)  
Actual: none

Command:

```bash
docker run --rm --entrypoint sh agent-latch:test -c 'command -v node npm npx gcc cc git || echo none'
```

Output (full, unedited):

```text
none
```

Exit code: `0`

### Check 5: Scan of demo project (read-only mount) — PASS

Expected: HIGH findings, exit code 1  
PASS rule: exit code 1 and at least one [HIGH] finding line  
Actual: exit 1, 4 HIGH finding(s): MAN001, MAN002, AG006, PY002

Command:

```bash
docker run --rm -v "$PWD/examples/vulnerable-agent:/src:ro" agent-latch:test scan . --plain --fail-on high
```

Output (full, unedited):

```text
AgentLatch scan: /src
Manifest: /src/agent-manifest.yaml
Findings: 12

[HIGH] MAN001 (ALR09) High-risk tool without human approval
  agent-manifest.yaml:29:1
  Tool 'run_shell' can perform high-impact actions with no approval gate declared. Require human confirmation or narrow the capability.
  Gate: ALR09 Human approval for sensitive actions
  OWASP Agentic: ASI02 Tool Misuse and Exploitation; ASI05 Unexpected Code Execution (RCE); ASI09 Human-Agent Trust Exploitation | confidence: medium
  Evidence: tool 'run_shell' capabilities: shell, filesystem:write; no requires_approval/human_in_the_loop/require_confirmation

[HIGH] MAN002 (ALR07) Tool grants wildcard permissions
  agent-manifest.yaml:40:1
  Tool 'file_manager' declares unbounded permissions. Scope it to the specific actions the agent needs.
  Gate: ALR07 Least-privilege tools
  OWASP Agentic: ASI02 Tool Misuse and Exploitation; ASI03 Identity and Privilege Abuse | confidence: high
  Evidence: tool 'file_manager' permissions: *

[HIGH] AG006 (ALR09) Human approval disabled for agent actions
  orchestrator.py:24:14
  UserProxyAgent runs model-written code with no human in the loop. A user or reviewer can be steered into trusting actions they never see. Keep a human confirmation step for code execution and other high-impact actions.
  Gate: ALR09 Human approval for sensitive actions
  OWASP Agentic: ASI09 Human-Agent Trust Exploitation; ASI05 Unexpected Code Execution (RCE) | confidence: high
  Evidence: UserProxyAgent(human_input_mode="NEVER", code execution on)

[HIGH] PY002 (ALR06) Subprocess uses shell=True
  tools.py:10:12
  Shell command construction can enable command injection, especially with untrusted or model-generated input.
  Gate: ALR06 Code execution containment
  OWASP Agentic: ASI05 Unexpected Code Execution (RCE); ASI02 Tool Misuse and Exploitation | confidence: high
  Evidence: call with shell=True

[MEDIUM] PRM002 (ALR01) Untrusted input interpolated into system prompt
  agent-manifest.yaml:9:28
  Agent 'ops-assistant' system_prompt inserts a user-controlled variable into system-level instructions. Pass user input in the user turn, delimited and labeled as data.
  Gate: ALR01 Prompt integrity
  OWASP Agentic: ASI01 Agent Goal Hijack | confidence: low
  Evidence: placeholder {user_input}

[MEDIUM] MAN003 (ALR03) Remote tool without authentication
  agent-manifest.yaml:36:1
  Tool 'crm_lookup' calls a remote endpoint with authentication explicitly disabled. Authenticate tool calls and scope credentials to this tool.
  Gate: ALR03 Tool and agent endpoint trust
  OWASP Agentic: ASI03 Identity and Privilege Abuse; ASI02 Tool Misuse and Exploitation | confidence: medium
  Evidence: tool 'crm_lookup' endpoint: http://crm.internal.example/api/v1; auth: none

[MEDIUM] AG004 (ALR09) High-risk agent tool without human approval
  orchestrator.py:9:1
  Tool 'write_report' lets the model write or delete files, and no approval gate was found in this file (LangGraph interrupt() or interrupt_before, HumanApprovalCallbackHandler, HumanInTheLoopMiddleware, needs_approval=True). Require human confirmation for these actions or narrow what the tool can do.
  Gate: ALR09 Human approval for sensitive actions
  OWASP Agentic: ASI02 Tool Misuse and Exploitation; ASI03 Identity and Privilege Abuse; ASI09 Human-Agent Trust Exploitation | confidence: medium
  Evidence: tool 'write_report' calls open(..., 'w'); no approval gate

[MEDIUM] AG007 (ALR08) Agent loop without an effective limit
  orchestrator.py:18:84
  max_iterations=None gives the agent no effective step limit. One bad step can then repeat or fan out without stopping. Set a small step limit, a timeout, or a circuit breaker.
  Gate: ALR08 Bounded execution
  OWASP Agentic: ASI08 Cascading Failures | confidence: medium
  Evidence: AgentExecutor(max_iterations=None)

[MEDIUM] ALR06-S02 Model-written code runs without a sandbox
  orchestrator.py:27:71
  use_docker=False runs model-written code on the host. A prompt-injected request then executes with the agent's own file, network, and credential access. Run generated code in a container or a sandboxed executor, or remove code execution from the agent.
  Gate: ALR06 Code execution containment
  OWASP Agentic: ASI05 Unexpected Code Execution (RCE); ASI02 Tool Misuse and Exploitation | confidence: high
  Evidence: UserProxyAgent(use_docker=False)

[MEDIUM] PRM002 (ALR01) Untrusted input interpolated into system prompt
  prompts/billing-system.md:2:20
  Prompt template for agent 'billing-agent' inserts a user-controlled variable into system-level instructions. Pass user input in the user turn, delimited and labeled as data.
  Gate: ALR01 Prompt integrity
  OWASP Agentic: ASI01 Agent Goal Hijack | confidence: low
  Evidence: placeholder {{ customer_message }}

[MEDIUM] PRM001 (ALR01) Prompt-injection signature in prompt
  prompts/ticket-summary.md:5:6
  Prompt template for agent 'ops-assistant' contains an instruction-override phrase commonly used in prompt injection. Check whether this text came from an untrusted source.
  Gate: ALR01 Prompt integrity
  OWASP Agentic: ASI01 Agent Goal Hijack | confidence: medium
  Evidence: "Ignore all previous instructions"

[MEDIUM] AG003 (ALR05) Untrusted web/tool output inserted into prompt
  tools.py:21:9
  Content fetched from the web or a search/loader tool reaches an LLM message unfenced, so instructions hidden in that content can hijack the agent (indirect prompt injection). Wrap it in delimiters such as <search_results> tags, tell the model to treat it as data, and limit what tools the agent can call afterwards.
  Gate: ALR05 Untrusted content isolation
  OWASP Agentic: ASI01 Agent Goal Hijack | confidence: low
  Evidence: web/tool output reaches HumanMessage content

OWASP Top 10 for Agentic Applications 2026 (informational mapping):
  ASI01 Agent Goal Hijack: 4 finding(s)
  ASI02 Tool Misuse and Exploitation: 6 finding(s)
  ASI03 Identity and Privilege Abuse: 3 finding(s)
  ASI04 Agentic Supply Chain Vulnerabilities: no findings from enabled checks
  ASI05 Unexpected Code Execution (RCE): 4 finding(s)
  ASI06 Memory & Context Poisoning: no findings from enabled checks
  ASI07 Insecure Inter-Agent Communication: no findings from enabled checks
  ASI08 Cascading Failures: 1 finding(s)
  ASI09 Human-Agent Trust Exploitation: 3 finding(s)
  ASI10 Rogue Agents: no findings from enabled checks

Selected static checks only; findings require human review.

✗ Failing (exit 1): 4 finding(s) at or above --fail-on high
  HIGH     MAN001 (ALR09)  agent-manifest.yaml:29  High-risk tool without human approval
  HIGH     MAN002 (ALR07)  agent-manifest.yaml:40  Tool grants wildcard permissions
  HIGH     AG006 (ALR09)   orchestrator.py:24      Human approval disabled for agent actions
  HIGH     PY002 (ALR06)   tools.py:10             Subprocess uses shell=True
Fix these, list accepted ones in .agent-latch-ignore (applied with --project-ignores), or raise --fail-on.
```

Exit code: `1`

### Check 6: Project mount is read-only — PASS

Expected: "Read-only file system", non-zero exit  
PASS rule: exit code is not 0 and output contains "Read-only file system"  
Actual: exit 1: touch: cannot touch '/src/x': Read-only file system

Command:

```bash
docker run --rm -v "$PWD/examples/vulnerable-agent:/src:ro" --entrypoint sh agent-latch:test -c 'touch /src/x'
```

Output (full, unedited):

```text
touch: cannot touch '/src/x': Read-only file system
```

Exit code: `1`

### Check 7: SARIF report — PASS

Expected: exit 0, 12 results in the SARIF  
PASS rule: docker exit 0, python3 count exit 0, and count is exactly 12  
Actual: exit 0, 12 result(s) in SARIF

**Step 1 of 3**

Command:

```bash
mkdir -p /tmp/agentlatch-proof-work/out
```

Output: none (the command printed nothing).

Exit code: `0`

**Step 2 of 3**

Command:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/examples/vulnerable-agent:/src:ro" -v /tmp/agentlatch-proof-work/out:/out agent-latch:test scan . --format sarif --output /out/agent-latch.sarif
```

Output (full, unedited):

```text
Wrote sarif report with 12 finding(s) to /out/agent-latch.sarif
```

Exit code: `0`

**Step 3 of 3**

Command:

```bash
python3 -I -c 'import json; d = json.load(open("/tmp/agentlatch-proof-work/out/agent-latch.sarif")); print(len(d["runs"][0]["results"]))'
```

Output (full, unedited):

```text
12
```

Exit code: `0`

### Check 8: Configuration error exit code — PASS

Expected: exit code 2  
PASS rule: exit code is exactly 2  
Actual: exit 2: agent-latch [scan] [path] [options]

Command:

```bash
docker run --rm -v "$PWD/examples/vulnerable-agent:/src:ro" agent-latch:test scan . --fail-on banana
```

Output (full, unedited):

```text
USAGE: agent-latch [scan] [path] [options]
agent-latch: error: argument --fail-on: invalid choice: 'banana' (choose from 'none', 'low', 'medium', 'high', 'critical')
```

Exit code: `2`

### Check 9: Runtime image: architecture, version, non-root, no Node.js/compiler — PASS

Expected: arm64 / agent-latch-runtime 0.5.0 / 10001 / none  
PASS rule: each of the four outputs is exactly the expected value, in order  
Actual: arm64 / agent-latch-runtime 0.5.0 / 10001 / none

**Step 1 of 4**

Command:

```bash
docker image inspect agent-latch-runtime:test --format '{{.Architecture}}'
```

Output (full, unedited):

```text
arm64
```

Exit code: `0`

**Step 2 of 4**

Command:

```bash
docker run --rm agent-latch-runtime:test --version
```

Output (full, unedited):

```text
agent-latch-runtime 0.5.0
```

Exit code: `0`

**Step 3 of 4**

Command:

```bash
docker run --rm --entrypoint id agent-latch-runtime:test -u
```

Output (full, unedited):

```text
10001
```

Exit code: `0`

**Step 4 of 4**

Command:

```bash
docker run --rm --entrypoint sh agent-latch-runtime:test -c 'command -v node npm npx gcc cc git || echo none'
```

Output (full, unedited):

```text
none
```

Exit code: `0`

### Check 10: Runtime demo — PASS

Expected: about ten event lines, then the list of files written  
PASS rule: exit 0, at least 8 '#N demo-server:' event lines, and a 'demo: files in' line  
Actual: exit 0, 10 event lines, files in runtime-logs/demo: trace.jsonl, payloads.jsonl, events.csv, gate-results.csv, normalized.jsonl, proxy.log

Command:

```bash
docker run --rm -v agentlatch-proof:/data agent-latch-runtime:test demo
```

Output (full, unedited):

```text
agent-latch-runtime: demo: calling the synthetic demo-server through the proxy
agent-latch-runtime: demo: importing the logs (1 gate(s))
agent-latch-runtime: #1 demo-server: tools/list -> 4 tool(s) [payload] | gates: 1 finding(s)
agent-latch-runtime: #2 demo-server: tools/call get_weather (city) [payload] | gates: 0 finding(s)
agent-latch-runtime: #3 demo-server: tools/call get_weather -> ok, 51 B in 4.7 ms [payload] | gates: 0 finding(s)
agent-latch-runtime: #4 demo-server: tools/call leaky_lookup (user) [payload] | gates: 0 finding(s)
agent-latch-runtime: #5 demo-server: tools/call leaky_lookup -> ok, 44 B in 2.6 ms [payload] | gates: 0 finding(s)
agent-latch-runtime: #6 demo-server: tools/call broken_tool (reason) [payload] | gates: 0 finding(s)
agent-latch-runtime: #7 demo-server: tools/call broken_tool -> error result, 17 B in 3.0 ms [payload] | gates: 0 finding(s)
agent-latch-runtime: #8 demo-server: prompts/list -> 1 prompt(s) | gates: 0 finding(s)
agent-latch-runtime: #9 demo-server: prompts/get summarize (topic) [payload] | gates: 0 finding(s)
agent-latch-runtime: #10 demo-server: prompts/get summarize -> 1 message(s) [payload] | gates: 0 finding(s)
agent-latch-runtime: demo: files in runtime-logs/demo: trace.jsonl, payloads.jsonl, events.csv, gate-results.csv, normalized.jsonl, proxy.log
```

Exit code: `0`

### Check 11: Log files are private — FAIL

Expected: -rw------- on the log files  
PASS rule: exit 0, at least one file, and every regular file line starts with -rw-------  
Actual: 6 file(s); not private: proxy.log

Command:

```bash
docker run --rm -v agentlatch-proof:/data --entrypoint ls agent-latch-runtime:test -la /data/runtime-logs/demo
```

Output (full, unedited):

```text
total 48
drwxr-xr-x 2 latch latch 4096 Nov  4 21:55 .
drwxr-xr-x 3 latch latch 4096 Nov  4 21:55 ..
-rw------- 1 latch latch 1654 Nov  4 21:55 events.csv
-rw------- 1 latch latch 1563 Nov  4 21:55 gate-results.csv
-rw------- 1 latch latch 8781 Nov  4 21:55 normalized.jsonl
-rw------- 1 latch latch 5561 Nov  4 21:55 payloads.jsonl
-rw-r--r-- 1 latch latch  492 Nov  4 21:55 proxy.log
-rw------- 1 latch latch 4643 Nov  4 21:55 trace.jsonl
```

Exit code: `0`

### Check 12: Real MCP over stdio (docker run -i) — PASS

Expected: server "weather", 4 tools, weather reply for Paris, container exit 0, every stdout line is JSON  
PASS rule: client exits 0, which it does only when all five of its own checks print PASS  
Actual: server "weather", 4 tools, reply "Weather in Paris: 18 degrees (metric), light rain.", container exit 0, all stdout JSON: True

Client source (`/tmp/agentlatch-proof-work/stdio_client.py`, deleted after the run):

```python
"""MCP stdio client for check 12: plays the AI app against the runtime image through docker run -i."""
import json
import subprocess
import sys
import threading

CMD = ["docker", "run", "-i", "--rm", "-v", "agentlatch-proof:/data", "agent-latch-runtime:test",
       "proxy", "--name", "weather", "--trace", "/data/t.jsonl", "--ledger", "/data/t.ledger.jsonl",
       "--", "python", "-m", "agent_latch.runtime.demo_server"]

proc = subprocess.Popen(CMD, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
stderr_lines = []
reader = threading.Thread(target=lambda: stderr_lines.extend(proc.stderr), daemon=True)
reader.start()
killer = threading.Timer(120, proc.kill)  # a hung container must not hang the proof run
killer.start()

stdout_lines = []  # every line the container wrote to stdout, verbatim
non_json = []


def read_line():
    line = proc.stdout.readline()
    if not line:
        return None
    line = line.rstrip("\n")
    stdout_lines.append(line)
    print("<<", line)
    try:
        return json.loads(line)
    except ValueError:
        non_json.append(line)
        return {}


def send(message):
    line = json.dumps(message)
    print(">>", line)
    proc.stdin.write(line + "\n")
    proc.stdin.flush()


def request(message):
    """Send a request and return the reply with the same id (None if stdout closed first)."""
    send(message)
    while True:
        reply = read_line()
        if reply is None or reply.get("id") == message["id"]:
            return reply


init = request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {},
    "clientInfo": {"name": "proof-client", "version": "1"}}})
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
listed = request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
called = request({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                  "params": {"name": "get_weather", "arguments": {"city": "Paris"}}})
proc.stdin.close()
while read_line() is not None:  # drain the rest, so every stdout line is checked
    pass
code = proc.wait()
killer.cancel()
reader.join(timeout=10)

server = ((init or {}).get("result") or {}).get("serverInfo", {}).get("name")
tools = [t.get("name") for t in ((listed or {}).get("result") or {}).get("tools", [])]
content = ((called or {}).get("result") or {}).get("content") or [{}]
text = content[0].get("text")
all_json = bool(stdout_lines) and not non_json

print()
print("server name:", server)
print("tools (%d): %s" % (len(tools), tools))
print("tools/call get_weather text:", text)
print("container exit code:", code)
print("stdout lines: %d, all parse as JSON: %s" % (len(stdout_lines), all_json))
print("container stderr (%d lines, verbatim):" % len(stderr_lines))
for line in stderr_lines:
    print(line.rstrip("\n"))

checks = {
    'server name is "weather"': server == "weather",
    "4 tools listed": len(tools) == 4,
    "weather reply for Paris": bool(text) and "Paris" in text,
    "container exit code 0": code == 0,
    "every stdout line parses as JSON": all_json,
}
for name, ok in checks.items():
    print(("PASS " if ok else "FAIL ") + name)
sys.exit(0 if all(checks.values()) else 1)
```

Command:

```bash
python3 -I /tmp/agentlatch-proof-work/stdio_client.py
```

Output (full, unedited):

```text
>> {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "proof-client", "version": "1"}}}
<< {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"logging":{},"prompts":{"listChanged":true},"resources":{"subscribe":false,"listChanged":true},"tools":{"listChanged":true}},"serverInfo":{"name":"weather","version":"4.1.4"}}}
>> {"jsonrpc": "2.0", "method": "notifications/initialized"}
>> {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
<< {"jsonrpc":"2.0","id":2,"result":{"tools":[{"_meta":{"fastmcp":{"tags":[]}},"annotations":{"readOnlyHint":true},"description":"Return a canned weather report for a city.","inputSchema":{"properties":{"city":{"type":"string"},"units":{"default":"metric","type":"string"}},"required":["city"],"type":"object","additionalProperties":false},"name":"get_weather","outputSchema":{"properties":{"result":{"type":"string"}},"required":["result"],"type":"object","x-fastmcp-wrap-result":true},"title":"Get Weather"},{"_meta":{"fastmcp":{"tags":[]}},"description":"Return a record that contains a credential-shaped value, to test redaction.","inputSchema":{"properties":{"user":{"type":"string"}},"required":["user"],"type":"object","additionalProperties":false},"name":"leaky_lookup","outputSchema":{"properties":{"result":{"type":"string"}},"required":["result"],"type":"object","x-fastmcp-wrap-result":true},"title":"Leaky Lookup"},{"_meta":{"fastmcp":{"tags":[]}},"description":"Always fail.","inputSchema":{"properties":{"reason":{"type":"string"}},"required":["reason"],"type":"object","additionalProperties":false},"name":"broken_tool","outputSchema":{"properties":{"result":{"type":"string"}},"required":["result"],"type":"object","x-fastmcp-wrap-result":true},"title":"Broken Tool"},{"_meta":{"fastmcp":{"tags":[]}},"annotations":{"readOnlyHint":true},"description":"Return weather text that carries a prompt-injection payload.","inputSchema":{"properties":{"city":{"type":"string"}},"required":["city"],"type":"object","additionalProperties":false},"name":"echo_injection","outputSchema":{"properties":{"result":{"type":"string"}},"required":["result"],"type":"object","x-fastmcp-wrap-result":true},"title":"Echo Injection"}]}}
>> {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "get_weather", "arguments": {"city": "Paris"}}}
<< {"jsonrpc":"2.0","id":3,"result":{"_meta":{"fastmcp":{"wrap_result":true},"io.modelcontextprotocol/serverInfo":{"name":"fake-weather","version":"4.1.4"}},"content":[{"text":"Weather in Paris: 18 degrees (metric), light rain.","type":"text"}],"isError":false,"structuredContent":{"result":"Weather in Paris: 18 degrees (metric), light rain."}}}

server name: weather
tools (4): ['get_weather', 'leaky_lookup', 'broken_tool', 'echo_injection']
tools/call get_weather text: Weather in Paris: 18 degrees (metric), light rain.
container exit code: 0
stdout lines: 3, all parse as JSON: True
container stderr (8 lines, verbatim):
agent-latch-runtime: monitoring 'weather' (preview; records traffic, never blocks)
[11/04/26 21:55:10] INFO     Starting MCP server 'weather' with transport.py:241
                             transport 'stdio'                                  
[11/04/26 21:55:11] INFO     Starting MCP server 'fake-weather' transport.py:241
                             with transport 'stdio'                             
agent-latch-runtime: tools/list -> 4 tool(s)
agent-latch-runtime: tools/call get_weather (city)
agent-latch-runtime: tools/call get_weather -> ok, 50 B in 4.2 ms
PASS server name is "weather"
PASS 4 tools listed
PASS weather reply for Paris
PASS container exit code 0
PASS every stdout line parses as JSON
```

Exit code: `0`

### Check 13: Ledger intact — PASS

Expected: AUDIT TRAIL UNANCHORED, exit 0  
PASS rule: exit 0 and output contains "AUDIT TRAIL UNANCHORED"  
Actual: exit 0: AUDIT TRAIL UNANCHORED — 3 record(s) verify locally, but nothing outside the machine proves the file was not rebuilt.

Command:

```bash
docker run --rm -v agentlatch-proof:/data agent-latch-runtime:test verify /data/t.ledger.jsonl
```

Output (full, unedited):

```text
AUDIT TRAIL UNANCHORED — 3 record(s) verify locally, but nothing outside the machine proves the file was not rebuilt.
```

Exit code: `0`

### Check 14: Ledger catches tampering (line 2 of /data/t.jsonl deleted) — PASS

Expected: AUDIT TRAIL DELETED, exit 1  
PASS rule: line deletion exits 0, then verify exits 1 and output contains "AUDIT TRAIL DELETED"  
Actual: exit 1: AUDIT TRAIL DELETED — records are missing; the log cannot be trusted.

**Step 1 of 2**

Command:

```bash
docker run --rm -v agentlatch-proof:/data --entrypoint sh agent-latch-runtime:test -c 'wc -l /data/t.jsonl && sed -i 2d /data/t.jsonl && wc -l /data/t.jsonl'
```

Output (full, unedited):

```text
3 /data/t.jsonl
2 /data/t.jsonl
```

Exit code: `0`

**Step 2 of 2**

Command:

```bash
docker run --rm -v agentlatch-proof:/data agent-latch-runtime:test verify /data/t.ledger.jsonl
```

Output (full, unedited):

```text
AUDIT TRAIL DELETED — records are missing; the log cannot be trusted.
  #2: the trace line this block sealed is gone
```

Exit code: `1`

### Check 15: HTTP safety lock — PASS

Expected: "--http must use a loopback address", exit 2  
PASS rule: exit code 2 and output contains "--http must use a loopback address"  
Actual: exit 2: agent-latch-runtime: --http must use a loopback address such as 127.0.0.1

Command:

```bash
docker run --rm --name agentlatch-proof-http agent-latch-runtime:test proxy --http 0.0.0.0:8770 --upstream-url https://example.com/mcp
```

Output (full, unedited):

```text
agent-latch-runtime: --http must use a loopback address such as 127.0.0.1
```

Exit code: `2`

### Check 16: Clean shutdown on docker stop — PASS

Expected: stop under 2 seconds, exit code 0  
PASS rule: docker stop exits 0, takes under 2.000 s, and the container's exit code is 0  
Actual: status before stop: running; stop took 0.13 s; container exit code 0

**Step 1 of 6**

Command:

```bash
docker run -d --name agentlatch-proof-stop -v agentlatch-proof:/data agent-latch-runtime:test import-logs --dir /data/runtime-logs/demo
```

Output (full, unedited):

```text
7f8e1f11d50584e9757b085ce8629babc8cc103fd75e0a9e1b05a305e63fa2c5
```

Exit code: `0`

**Step 2 of 6**

Command:

```bash
sleep 3
```

Output: none (the command printed nothing).

Exit code: `0`

**Step 3 of 6**

Command:

```bash
docker inspect -f '{{.State.Status}}' agentlatch-proof-stop
```

Output (full, unedited):

```text
running
```

Exit code: `0`

**Step 4 of 6**

Command:

```bash
TIMEFORMAT='docker stop took %3R seconds'; time docker stop agentlatch-proof-stop
```

Output (full, unedited):

```text
agentlatch-proof-stop
docker stop took 0.130 seconds
```

Exit code: `0`

**Step 5 of 6**

Command:

```bash
docker inspect -f '{{.State.ExitCode}}' agentlatch-proof-stop
```

Output (full, unedited):

```text
0
```

Exit code: `0`

**Step 6 of 6**

Command:

```bash
docker logs agentlatch-proof-stop
```

Output (full, unedited):

```text
agent-latch-runtime: importing /data/runtime-logs/demo/trace.jsonl into /data/runtime-logs/demo/events.csv with 1 gate(s); following new lines (Ctrl+C to stop)
```

Exit code: `0`

## 5. Repository unchanged

Before the builds:

```text
$ git status --porcelain
[exit code 0]
$ git rev-parse HEAD
6be6bf6b5457a99366d9b75b725772fc4a9ff2a9
[exit code 0]
```

After the last check:

```text
$ git status --porcelain
[exit code 0]
$ git rev-parse HEAD
6be6bf6b5457a99366d9b75b725772fc4a9ff2a9
[exit code 0]
```

Before and after match: **yes**. (An empty `git status --porcelain` means no modified or untracked files.)

## 6. Limits of this test

- It tests images built locally from branch `claude/relaxed-carson-hodmui`, not images published to GHCR.
- It does not test a real AI app such as Claude Desktop. Check 12 uses a small Python client that speaks MCP over stdio the same way.
- Only the native linux/arm64 images were built and run; the amd64 variants were not tested on this Mac.
- The builds reused Docker's layer cache from earlier builds of the same Dockerfile on this Mac (the steps marked CACHED in the build output).
