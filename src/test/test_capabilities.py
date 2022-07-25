from testtools import TestCase
from testtools.matchers import Equals
from hypothesis import given

from tahoe_capabilities.strategies import capabilities
from tahoe_capabilities import Capability, danger_real_capability_string, capability_from_string

class ParseTests(TestCase):
    @given(capabilities())
    def test_from_string_roundtrip(self, cap: Capability) -> None:
        """
        All capabilities round-trip through ``capability_from_string`` and
        ``danger_real_capability_string``.
        """
        cap_str = danger_real_capability_string(cap)
        cap_parsed = capability_from_string(cap_str)
        self.assertThat(cap_parsed, Equals(cap))
