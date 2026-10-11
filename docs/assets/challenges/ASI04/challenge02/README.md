# ASI4-Labs-Demo — Dependency Confusion Through Untrusted Package Installation

### GitHub Link
[https://github.com/syedDS/ASI4-Labs-Demo.git](https://github.com/syedDS/ASI4-Labs-Demo.git)

### Target Vulnerable File
* `vulnerable-agent/app.py` `install_package()` (lines 1160–1225)

### Vulnerability
The `/api/install-package` endpoint accepts an arbitrary package name from the HTTP request and executes `pip install` against `PYPI_INDEX_URL` without package provenance, signature, hash, or version verification. The downloaded package is subsequently imported with `python -c`, allowing package installation to become arbitrary code execution inside the agent container.