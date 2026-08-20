"""The nine-cell classification table, tabulated exhaustively.

The point of writing every cell out is that a duplicated metric shows up as two
identical columns. That is how F3 -- "classification agreement" and
"availability agreement" being the same predicate -- survived two review rounds
while buried inside the counting loop.
"""

from __future__ import annotations

import itertools
import unittest

from slot_audit.audit import classify_position
from slot_audit.verdict import GroundTruthState, ProviderSlotState, Verdict

PRESENT = ProviderSlotState.PRESENT
ABSENT = ProviderSlotState.ABSENT
UNCOVERED = ProviderSlotState.UNCOVERED
PRODUCED = GroundTruthState.PRODUCED
SKIPPED = GroundTruthState.SKIPPED
UNKNOWN = GroundTruthState.UNKNOWN

# (provider state, ground truth) -> (verdict, agrees_with_anchor, covered)
TABLE: dict[tuple[ProviderSlotState, GroundTruthState], tuple[Verdict, bool | None, bool]] = {
    (PRESENT, PRODUCED): (Verdict.PRESENT, True, True),
    (PRESENT, SKIPPED): (Verdict.GROUND_TRUTH_CONFLICT, False, True),
    (PRESENT, UNKNOWN): (Verdict.INDETERMINATE, None, True),
    (ABSENT, PRODUCED): (Verdict.PROVIDER_HOLE, False, True),
    (ABSENT, SKIPPED): (Verdict.PROTOCOL_SKIPPED, True, True),
    (ABSENT, UNKNOWN): (Verdict.INDETERMINATE, None, True),
    (UNCOVERED, PRODUCED): (Verdict.INDETERMINATE, None, False),
    (UNCOVERED, SKIPPED): (Verdict.INDETERMINATE, None, False),
    (UNCOVERED, UNKNOWN): (Verdict.INDETERMINATE, None, False),
}


class ClassificationTableTests(unittest.TestCase):
    def test_the_table_covers_every_combination(self) -> None:
        combinations = set(itertools.product(ProviderSlotState, GroundTruthState))

        self.assertEqual(set(TABLE), combinations)
        self.assertEqual(len(TABLE), 9)

    def test_every_cell_matches_the_implementation(self) -> None:
        for (state, truth), expected in TABLE.items():
            with self.subTest(state=state.value, truth=truth.value):
                outcome = classify_position(state, truth)

                self.assertEqual(
                    (outcome.verdict, outcome.agrees_with_anchor, outcome.covered),
                    expected,
                )

    def test_agreement_and_coverage_are_not_the_same_column(self) -> None:
        """The check that would have caught F3 immediately."""

        agreement = [TABLE[key][1] for key in sorted(TABLE, key=str)]
        coverage = [TABLE[key][2] for key in sorted(TABLE, key=str)]

        self.assertNotEqual(agreement, coverage)
        # Concretely: an uncovered position is never scoreable for agreement,
        # yet it is unambiguously a coverage miss. One value cannot say both.
        uncovered = classify_position(UNCOVERED, PRODUCED)
        self.assertIsNone(uncovered.agrees_with_anchor)
        self.assertFalse(uncovered.covered)

    def test_not_asking_is_never_scored_as_disagreement(self) -> None:
        for truth in GroundTruthState:
            with self.subTest(truth=truth.value):
                outcome = classify_position(UNCOVERED, truth)

                self.assertIs(outcome.verdict, Verdict.INDETERMINATE)
                self.assertIsNone(outcome.agrees_with_anchor)
                self.assertFalse(outcome.determinate)

    def test_an_unverifiable_anchor_never_produces_a_hole(self) -> None:
        for state in ProviderSlotState:
            with self.subTest(state=state.value):
                outcome = classify_position(state, UNKNOWN)

                self.assertIs(outcome.verdict, Verdict.INDETERMINATE)
                self.assertIsNot(outcome.verdict, Verdict.PROVIDER_HOLE)

    def test_only_one_cell_yields_a_provider_hole(self) -> None:
        holes = [
            key for key, value in TABLE.items() if value[0] is Verdict.PROVIDER_HOLE
        ]

        self.assertEqual(holes, [(ABSENT, PRODUCED)])

    def test_the_function_is_total(self) -> None:
        for state, truth in itertools.product(ProviderSlotState, GroundTruthState):
            with self.subTest(state=state.value, truth=truth.value):
                self.assertIsInstance(classify_position(state, truth).verdict, Verdict)


class CodeSemanticsTableTests(unittest.TestCase):
    """The other safety-critical table: what each RPC code licenses."""

    def test_every_declared_code_is_classified_exactly_once(self) -> None:
        from slot_audit.solana_codes import CODE_SEMANTICS, RpcErrorCode

        self.assertEqual(set(CODE_SEMANTICS), {int(code) for code in RpcErrorCode})
        for code, item in CODE_SEMANTICS.items():
            with self.subTest(code=code):
                exclusive = (item.denies_block, item.retryable, item.retention_limit)
                self.assertLessEqual(sum(exclusive), 1)
                self.assertTrue(item.meaning)

    def test_only_skip_codes_deny_a_block(self) -> None:
        from slot_audit.solana_codes import DENIAL_CODES, RpcErrorCode

        self.assertEqual(
            DENIAL_CODES,
            frozenset(
                {
                    int(RpcErrorCode.SLOT_SKIPPED),
                    int(RpcErrorCode.LONG_TERM_STORAGE_SLOT_SKIPPED),
                }
            ),
        )

    def test_retention_codes_are_never_denials(self) -> None:
        from slot_audit.solana_codes import DENIAL_CODES, RETENTION_CODES

        self.assertEqual(DENIAL_CODES & RETENTION_CODES, frozenset())

    def test_retryable_codes_are_never_denials(self) -> None:
        from slot_audit.solana_codes import DENIAL_CODES, RETRYABLE_CODES

        self.assertEqual(DENIAL_CODES & RETRYABLE_CODES, frozenset())

    def test_an_unknown_code_licenses_nothing(self) -> None:
        from slot_audit import solana_codes

        for code in (None, -99999, 0):
            with self.subTest(code=code):
                self.assertFalse(solana_codes.denies_block(code))
                self.assertFalse(solana_codes.is_retryable(code))
                self.assertFalse(solana_codes.is_retention_limit(code))

    def test_the_table_states_that_it_is_unverified(self) -> None:
        """It is a transcription, not an upstream guarantee, and says so."""

        from slot_audit import solana_codes

        doc = " ".join((solana_codes.__doc__ or "").split())
        self.assertIn("have **not** been verified against a live node", doc)
        self.assertIn("not an upstream guarantee", doc)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
