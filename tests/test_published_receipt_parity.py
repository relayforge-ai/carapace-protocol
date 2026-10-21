"""The release workflow builds python/, while root imports also serve consumers."""
from pathlib import Path


def test_published_security_modules_and_vectors_match_root():
    root = Path(__file__).resolve().parents[1]
    for name in ('enforce.py', 'receipt.py', 'receipt_protocol.py'):
        assert (root / 'carapace' / name).read_bytes() == (root / 'python/carapace' / name).read_bytes()
    assert (root / 'test-vectors/receipt-v2.json').read_bytes() == (root / 'python/test-vectors/receipt-v2.json').read_bytes()
