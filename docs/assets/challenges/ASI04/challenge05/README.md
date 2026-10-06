# Challenge: ECC / Wildcard `pip install *` Pre-Approval in Stack Permissions (Challenge 05)

## 1. Upstream Source Repository

**GitHub Link:** https://github.com/affaan-m/ECC

**Target Vulnerable File:** [`config/project-stack-mappings.json`](https://github.com/affaan-m/ECC/blob/ef648e01899ba3e8dc6371642deaaf64b4477775/config/project-stack-mappings.json#L159-L162) (Lines 159–162)

## 2. What is the Vulnerability?

ECC's stack map, which `/project-init` uses as its reference when proposing agent permissions, pre-approves `pip install *` and `python *` for Python projects while denying only `pip install --user *`, so once applied the agent can install any package name, index URL, or VCS source without a per-install prompt. A typosquatted, hallucinated ("slopsquatted"), or prompt-injected package name therefore runs its install-time code on the developer's machine, and the same allow-list is repeated for the other Python stacks at lines 485 and 512.
