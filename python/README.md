# carapace-sdk Python package

Python package for the Carapace Protocol `v0.4.0` trust stack.

```bash
pip install carapace-sdk
```

```python
from carapace import enforce, make_expires_at

card = {
    "id": "agent-1",
    "capabilities": [{"id": "carapace:read:calendar"}],
    "expires_at": make_expires_at(ttl_hours=24),
}

enforce(card, "carapace:read:calendar")
```

The package source lives in `python/carapace`; the project source of truth is
https://github.com/relayforge-ai/carapace-protocol.

## 0.5.1 corrective release

Deploy ARIA 0.5.1 before upgrading receipt producers. New receipts bind the complete v2 envelope; legacy verification now returns false, and expiry enforcement rejects invalid and expired cards. See the [migration guide](https://github.com/relayforge-ai/carapace-protocol/blob/main/docs/RECEIPTS_V2.md) for compatibility and rollback limits.
