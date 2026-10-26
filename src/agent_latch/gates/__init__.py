"""Runtime gate plugin namespace.

Each gate module exports a unique string ``GATE_ID`` and an
``evaluate(event: dict) -> {"findings": list}`` function. The importer supplies each gate with
the same payload-event JSON object and writes a common result envelope to its CSV output.

``alr04`` ships with the package. It is a monitor-only preview: it reports findings and never
blocks. The runtime report lists findings only.

``agent-latch --runtime-result`` prints every gate's alerts from ``gate-results.csv``. A finding
is included when ``is_finding`` is true, or when that key is absent and ``outcome`` is ``FAIL``
or ``INCONCLUSIVE``. These fields are what the report reads, for this gate and later ones:
``rule_id``, ``severity``, ``message``, ``owasp``, ``family`` (the title), ``entity.server``,
``entity.tool``, and ``evidence`` entries with ``signal`` and ``field``. Optional ``path``,
``line``, and ``column`` are the source location. Without them, the report looks up
``entity.tool`` as a function in the project and uses that function's docstring line.
"""
