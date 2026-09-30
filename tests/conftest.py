from __future__ import annotations

from datetime import date

import pytest

from expiry.config import DEFAULTS, Config, _merge
from expiry.db import Store

TODAY = date(2026, 9, 30)


def make_config(**overrides) -> Config:
    data = _merge(DEFAULTS, {"timezone": "UTC", "database": ":memory:"})
    for dotted, value in overrides.items():
        node = data
        parts = dotted.split("__")
        for p in parts[:-1]:
            node = node[p]
        node[parts[-1]] = value
    return Config(data, None)


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


@pytest.fixture
def cfg():
    return make_config(notify__emails=["ops@example.com"], email__smtp__host="localhost",
                       email__from="expiry@example.com")
