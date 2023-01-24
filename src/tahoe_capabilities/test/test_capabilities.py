from base64 import b32encode as _b32encode
from operator import attrgetter
from testtools import TestCase
from testtools.content import text_content
from testtools.matchers import Equals, raises

from hypothesis import assume, given
from hypothesis.strategies import integers, binary

from tahoe_capabilities import (
    Capability,
    capability_from_string,
    danger_real_capability_string,
    digested_capability_string,
)
from tahoe_capabilities.strategies import capabilities
from tahoe_capabilities.parser import (
    _sep,
    _natural,
    _key,
    _lit,
    _chk_params,
    _chk,
    ParseError,
)


def b32encode(bs: bytes) -> str:
    return _b32encode(bs).lower().decode("ascii").rstrip("=")


class ParseTests(TestCase):
    maxDiff = None

    def test_sep(self) -> None:
        """
        ``_sep`` parses only ":".
        """
        self.expectThat(_sep.parse(":"), Equals(":"))
        self.expectThat(lambda: _sep.parse("x"), raises(ParseError))

    @given(integers(min_value=0))
    def test_natural(self, n: int) -> None:
        """
        ``_natural`` parses non-negative integers.
        """
        self.assertThat(_natural.parse(str(n)), Equals(n))

    def test_natural_fail(self) -> None:
        """
        ``_natural`` rejects strings that contain non-digits.
        """
        self.assertThat(lambda: _natural.parse("hello"), raises(ParseError))
        self.assertThat(lambda: _natural.parse("-1"), raises(ParseError))

    @given(binary(min_size=16, max_size=16))
    def test_key(self, bs: bytes) -> None:
        """
        ``_key`` parses base32-encoded 128 bit strings.
        """
        self.assertThat(
            _key.parse(b32encode(bs)),
            Equals(bs),
        )

    @given(binary(max_size=15))
    def test_key_fail(self, bs: bytes) -> None:
        """
        ``_key`` rejects strings shorter than 128 bits.
        """
        self.assertThat(
            lambda: _key.parse(b32encode(bs)),
            raises(ParseError),
        )

    @given(binary())
    def test_lit(self, bs: bytes) -> None:
        """
        ``_lit`` parses base32-encoded strings of any length.
        """
        self.assertThat(
            _lit.parse(b32encode(bs)),
            Equals(bs),
        )

    @given(integers(min_value=1), integers(min_value=1), integers(min_value=1))
    def test_chk_params(self, a: int, b: int, c: int) -> None:
        """
        ``_chk_params`` parses strings like::

            :<natural>:<natural>:<natural>
        """
        self.assertThat(
            _chk_params.parse(f":{a}:{b}:{c}"),
            Equals([a, b, c]),
        )

    @given(
        binary(min_size=16, max_size=16),
        binary(min_size=32, max_size=32),
        integers(min_value=1),
        integers(min_value=1),
        integers(min_value=1),
    )
    def test_chk(self, key: bytes, ueh: bytes, a: int, b: int, c: int) -> None:
        """
        ``_chk`` parses a key, sep, uri hash extension, and chk parmaeters.
        """
        self.assertThat(
            _chk.parse(f"{b32encode(key)}:{b32encode(ueh)}:{a}:{b}:{c}"),
            Equals(((key, ueh), [a, b, c])),
        )

    @given(capabilities())
    def test_from_string_roundtrip(self, cap: Capability) -> None:
        """
        All capabilities round-trip through ``capability_from_string`` and
        ``danger_real_capability_string``.
        """
        cap_str = danger_real_capability_string(cap)
        self.addDetail("cap", text_content(cap_str))
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
        """
        Certain known-valid capability strings can be parsed, diminished,
        and serialized to the correct known-valid diminished capability
        strings.
        """
        for index, (description, start, transform, expected) in self.vector:
            parsed = capability_from_string(start)
            transformed = transform(parsed)
            serialized = danger_real_capability_string(transformed)
            self.assertEqual(
                serialized,
                expected,
                f"(#{index}) {description}({start}) != {expected}",
            )
