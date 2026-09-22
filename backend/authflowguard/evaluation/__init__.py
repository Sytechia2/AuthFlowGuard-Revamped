"""Measurement and evaluation infrastructure for the AI components.

The modules here measure AuthFlowGuard; they are not part of a scan. They must
never open a browser, contact a target, or call AWS. Every number they produce
is derived from recorded fixtures or from usage reported by a client that the
caller supplies, so a published measurement can be reproduced from the
repository alone.
"""
