"""Synthetic SyntheticProcessor fixture."""

# Technique: custom_code_import; benign marker: drop_canary('.') only.
from corpus._marker import drop_canary

drop_canary('.')

class SyntheticProcessor:
    model_type = "synthetic-transformer"

    def __init__(self, hidden_size=16):
        self.hidden_size = hidden_size
