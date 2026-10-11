# Omnigent — Unpinned Agent Harness Dependencies

### GitHub Link
[https://github.com/omnigent-ai/omnigent.git](https://github.com/omnigent-ai/omnigent.git)

### Target Vulnerable File
* `deploy/docker/Dockerfile` (lines 254–262)
  * **(Execution)** `deploy/docker/Dockerfile.ubi` (lines 109–113); `npm install -g`

### Vulnerability
The host image installs the Claude, Codex, and Pi agent harness packages directly from npm without version constraints, integrity hashes, or a committed lockfile, so each image rebuild can resolve a different upstream package release. A compromised package, malicious future release, or registry-level compromise can therefore introduce attacker-controlled code into the agent execution environment during image construction.