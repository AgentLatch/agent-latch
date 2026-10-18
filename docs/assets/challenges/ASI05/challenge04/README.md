# Challenge: [RD-Agent / Unsanitized Shell Interpolation in QlibCondaEnv.prepare] (Challenge 04)

## 1. Upstream source repository
- GitHub Link: https://github.com/microsoft/RD-Agent
- Version analyzed: archive upload
- Target vulnerable file(s): rdagent/utils/env.py
  - QlibCondaConf (lines 848-850)
  - QlibCondaEnv.prepare (lines 855-877)
  - _CONDA_ENV_NAME_RE / _prepare_conda_env — the safe pattern, same file (lines 891-951)

## 2. What is the vulnerability?
- `QlibCondaConf.conda_env_name` (env.py:848-850) is a settings field with no format constraint,
  and `QlibCondaEnv.prepare` (env.py:855-877) splices that value unescaped into four separate
  `subprocess.check_call(f"... -n {self.conf.conda_env_name} ...", shell=True)` calls. The same
  file defines a safe pattern for exactly this operation — `_prepare_conda_env` (env.py:922-951)
  validates the env name against `_CONDA_ENV_NAME_RE` and uses an argv-list `subprocess.check_call`
  instead of a shell string — and that helper is used by the sibling `FTCondaEnv`/`BenchmarkCondaEnv`
  classes, but `QlibCondaEnv.prepare` was never migrated to it, leaving a direct shell-injection path
  wherever `conda_env_name` can be influenced by configuration, a per-experiment identifier, or any
  value not fully controlled by a trusted operator.