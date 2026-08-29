"""The FCMP++ engine: the circuit, the prover and the verifier.
"""

from importlib import resources

# The consensus generators ship inside the package, so they resolve the same way
# whether the tree is run in place or installed.
PARAMS_FILE = str(resources.files(__name__) / "data" / "input_params.txt")

__all__ = ["PARAMS_FILE"]
