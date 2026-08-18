"""Synthetic BetaModel fixture."""

class BetaModel:
    model_type = "synthetic-transformer"

    def __init__(self, hidden_size=16):
        self.hidden_size = hidden_size
