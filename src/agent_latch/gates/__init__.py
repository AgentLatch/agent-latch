"""Runtime gate plugin namespace.

Each gate module exports a unique string ``GATE_ID`` and an
``evaluate(event: dict) -> {"findings": list}`` function. The importer supplies each gate with
the same payload-event JSON object and writes a common result envelope to its CSV output.
"""
