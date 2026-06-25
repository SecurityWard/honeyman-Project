# Agent dev probes.
#
# The test_*.py files in this directory are standalone async scripts the
# original author used to manually exercise each detector against the
# rule engine. They print to stdout rather than asserting, so they are
# NOT runnable under pytest unmodified — that's why ci.yml skips them.
#
# Useful for hands-on debugging of a new rule or detector change. Run
# directly: `python tests/test_usb_detector.py`.
