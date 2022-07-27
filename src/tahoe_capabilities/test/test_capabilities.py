from operator import attrgetter
from unittest import TestCase

from hypothesis import assume, given

from tahoe_capabilities import (
    Capability,
    capability_from_string,
    danger_real_capability_string,
    digested_capability_string,
)
from tahoe_capabilities.strategies import capabilities


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
    def test_digested_capability_string_distinct(
        self, cap_a: Capability, cap_b: Capability
    ) -> None:
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


verifier = attrgetter("verifier")
reader = attrgetter("reader")


class VectorTests(TestCase):
    """
    Test Tahoe-Capabilities behavior on hard-coded values against
    known-correct test vectors extracted from Tahoe-LAFS.
    """

    # raw values from build_test_vector.sh
    CHK = "URI:CHK:intrb3iinc7ushk6krxnbqrvfm:iyi4bqhr45ib4hzyvuv2tdifoqgt7enpavd7szdpiadxoxz6mkrq:1:3:120"
    CHK_VERIFY = "URI:CHK-Verifier:6iimmnn2zkv6uan23ehz3l2zdm:iyi4bqhr45ib4hzyvuv2tdifoqgt7enpavd7szdpiadxoxz6mkrq:1:3:120"

    # TODO: Hard to make CHK:DIR2: from CLI.

    SSK = "URI:SSK:5mcjppxck7re2kzdol7b5ojmgi:jwjbsudn4z452bo2eqbjdzrvo2f72tav3xyb2llfnfjjsopczi5q"
    SSK_RO = "URI:SSK-RO:ff4ugthp3xvwmoffk2yod4sody:jwjbsudn4z452bo2eqbjdzrvo2f72tav3xyb2llfnfjjsopczi5q"
    SSK_VERIFY = "URI:SSK-Verifier:arzawcbttbim763un3qoncffdq:jwjbsudn4z452bo2eqbjdzrvo2f72tav3xyb2llfnfjjsopczi5q"

    SSK_DIR2 = "URI:DIR2:5wp23saa7oxr2lw6ly7iawyndy:4j7ki5a64zkzo2jpynqdacgejtpibpd5k25eexzdidnheaczsxlq"
    SSK_DIR2_RO = "URI:DIR2-RO:duhddpu57stxpe3hcuoldnokja:4j7ki5a64zkzo2jpynqdacgejtpibpd5k25eexzdidnheaczsxlq"
    SSK_DIR2_VERIFY = "URI:DIR2-Verifier:4fpljynygrrc42jyjzjrjvmyje:4j7ki5a64zkzo2jpynqdacgejtpibpd5k25eexzdidnheaczsxlq"

    MDMF = "URI:MDMF:p2xoe4uu64rqa5fi6xz3t5wpvu:zsaeyn5noivpixiu6uadlz2mu6r2alcmgrur2efdwadx4agxo6ua"
    MDMF_RO = "URI:MDMF-RO:fxyg6lh7y6al33npw2jqf7fmii:zsaeyn5noivpixiu6uadlz2mu6r2alcmgrur2efdwadx4agxo6ua"
    MDMF_VERIFY = "URI:MDMF-Verifier:cwbkz6mpgeb7tdfboohdjuoxey:zsaeyn5noivpixiu6uadlz2mu6r2alcmgrur2efdwadx4agxo6ua"

    MDMF_DIR2 = "URI:DIR2-MDMF:vgqyl4thexeghedpbkao2n42sq:3sspyogz6whnekcda4yd6zv7xrzx2ylwuexxsgrlp6psnzrkocqq"
    MDMF_DIR2_RO = "URI:DIR2-MDMF-RO:q67pk7haitbdklvahedujy2pt4:3sspyogz6whnekcda4yd6zv7xrzx2ylwuexxsgrlp6psnzrkocqq"
    MDMF_DIR2_VERIFY = "URI:DIR2-MDMF-Verifier:plcl33iztk3z3ii6rumj3pw7ma:3sspyogz6whnekcda4yd6zv7xrzx2ylwuexxsgrlp6psnzrkocqq"

    vector = enumerate(
        [
            ("verifier", CHK, verifier, CHK_VERIFY),
            ("verifier", SSK_RO, verifier, SSK_VERIFY),
            ("verifier", SSK_DIR2_RO, verifier, SSK_DIR2_VERIFY),
            ("verifier", MDMF_RO, verifier, MDMF_VERIFY),
            ("verifier", MDMF_DIR2_RO, verifier, MDMF_DIR2_VERIFY),
            ("reader", SSK, reader, SSK_RO),
            ("reader", SSK_DIR2, reader, SSK_DIR2_RO),
            ("reader", MDMF, reader, MDMF_RO),
            ("reader", MDMF_DIR2, reader, MDMF_DIR2_RO),
        ]
    )

    def test_vector(self) -> None:
        for index, (description, start, transform, expected) in self.vector:
            self.assertEqual(
                danger_real_capability_string(transform(capability_from_string(start))),
                expected,
                f"(#{index}) {description}({start}) != {expected}",
            )
