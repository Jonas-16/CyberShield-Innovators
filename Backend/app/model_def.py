from __future__ import annotations

import torch.nn as nn


class ZeroDayDetector(nn.Module):
    def __init__(self, input_dim: int):
        super().__init__()
        # Must match checkpoint key layout: net.0, net.3, net.6, net.8
        self.net = nn.Sequential(
            nn.Linear(input_dim, 1024),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(1024, 512),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(512, 128),
            nn.ReLU(),
            nn.Linear(128, 1),
        )

    def forward(self, x):
        return self.net(x)
