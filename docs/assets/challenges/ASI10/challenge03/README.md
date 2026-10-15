# Challenge: AutoGPT / Unlimited Continuous Mode and Self-Granted Permissions (Challenge 03)

## 1. Upstream Source Repository

* GitHub Link: https://github.com/Significant-Gravitas/AutoGPT
* Target Vulnerable File: classic/original_autogpt/autogpt/app/config.py (Lines 87-88); classic/original_autogpt/autogpt/app/main.py (Lines 594-600); classic/forge/forge/config/workspace_settings.py (Lines 21-61)

## 2. What is the Vulnerability?

* ASI10 vectors: #5 Runaway Autonomy & Missing Circuit Breakers; #4 Persistent Malicious Backdoors in Agent Runtime.
* Classic AutoGPT defaults to `continuous_mode = True` with `continuous_limit = 0` (config.py lines 87-88), which `_get_cycle_budget` turns into `math.inf` (main.py lines 594-600), so by default the main loop never runs out of cycles and stops only when the agent calls finish or the user presses Ctrl+C. Its default workspace permissions pre-approve `write_file({workspace}/**)` while the permission file itself lives inside that workspace at `.autogpt/autogpt.yaml` and is reloaded on every start (workspace_settings.py lines 21-61), so the agent can write itself new allow rules that silently persist into future sessions.
