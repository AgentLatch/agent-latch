# Open WebUI — Unverified Remote Tool Source Import

### GitHub Link
[https://github.com/open-webui/open-webui.git](https://github.com/open-webui/open-webui.git)

### Target Vulnerable File
* `backend/open_webui/routers/tools.py` `load_tool_from_url()` (lines 264–300)
  * **(Execution)** `backend/open_webui/routers/tools.py` `create_new_tools()` (lines 346–396); `backend/open_webui/utils/plugin.py` `load_tool_module_by_id()` (lines 206–241)

### Vulnerability
Open WebUI allows an administrator to import Python tool source directly from an arbitrary URL and provides no cryptographic signature, hash, commit pin, publisher verification, or source allowlist before the downloaded source is accepted as a tool. The imported source can subsequently enter `load_tool_module_by_id()`, where the contents are executed with Python `exec()`, so compromise or replacement of the remote tool repository can turn a legitimate tool import into arbitrary server-side code execution.