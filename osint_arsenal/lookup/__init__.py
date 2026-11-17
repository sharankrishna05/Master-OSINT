from .engine import LookupEngine, run_lookup
from .consensus import compute_verdict
from .graph import EvidenceGraph
from .modules.loader import load_all

# Ensure built-in and JSON modules are registered
load_all()
