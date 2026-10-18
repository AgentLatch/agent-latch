# Challenge: [AIOS / Unescaped String Interpolation into Executed Python Code (switch_applications)] (Challenge 03)

## 1. Upstream source repository
- GitHub Link: https://github.com/agiresearch/AIOS
- Version analyzed: archive upload
- Target vulnerable file(s):
  - aios/tool/mcp_server.py (lines 73-98)
  - aios/tool/virtual_env/controllers/python.py (lines 112-142)

## 2. What is the vulnerability?
- `switch_applications` (mcp_server.py:73-98) builds a raw Python source string
  (`UBUNTU_APP_SETUP`) and inserts its `app_code` MCP tool parameter into it with a naive
  `.replace("APP_NAME", app_code)` (line 97) — no escaping or quoting — even though other tools in
  the same file (`typing`, `drag_and_drop`) correctly wrap string input in `repr()` before embedding
  it. The unescaped value lands inside a single-quoted Python string literal
  (`difflib.get_close_matches('APP_NAME', ...)`), so any `app_code` containing a single quote breaks
  out of that literal and injects arbitrary Python statements into the generated source, which is
  then sent via `execute_command`/`execute_python_command` (python.py:112-142) as an HTTP POST to
  the target VM's `/execute` endpoint, where it is executed with full code-execution privilege
  inside the VM.