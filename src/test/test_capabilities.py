from unittest import TestCase
from hypothesis import given, assume

from tahoe_capabilities.strategies import capabilities
from tahoe_capabilities import Capability, danger_real_capability_string, capability_from_string, digested_capability_string

class ParseTests(TestCase):
    maxDiff = None

    @given(capabilities())
    def test_from_string_roundtrip(self, cap: Capability) -> None:
        """
        All capabilities round-trip through ``capability_from_string`` and
        ``danger_real_capability_string``.
        """
        cap_str = danger_real_capability_string(cap)
        cap_parsed = capability_from_string(cap_str)
        self.assertEqual(cap_parsed, cap)

    @given(capabilities())
    def test_digest_capability_not_real(self, cap: Capability) -> None:
        """
        ```digested_capability_string`` returns a different result than
        ``danger_real_capability_string``.
        """
        real = danger_real_capability_string(cap)
        digested = digested_capability_string(cap)

        # They are not exactly the same.
        self.assertNotEqual(real, digested)

    @given(capabilities(), capabilities())
    def test_digested_capability_string_distinct(self, cap_a: Capability, cap_b: Capability) -> None:
        """
        Two different capabilities produce different outputs from
        ``digested_capability_string``.
        """
        assume(cap_a != cap_b)

        # If we digest a capability down to 8 bytes (as we do) then we have 64
        # bits of entropy and the chance of collision in ouputs for any two
        # arbitrary inputs is 1 in 2^64.  If we test 10,000 pairs (or 50 test
        # runs, if Hypothesis gives us 200 examples per test run) per day then
        # we would expect a collision after 1664 years.  So, hopefully we get
        # away with this assertion even though it does not hold for all
        # inputs.
        self.assertNotEqual(
            digested_capability_string(cap_a),
            digested_capability_string(cap_b),
        )
