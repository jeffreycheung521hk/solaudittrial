"""Signed reconciliation of one legacy SPL Token mint."""

from __future__ import annotations

import unittest

from slot_audit.token import (
    LEGACY_TOKEN_PROGRAM_ID,
    AccountState,
    DuplicatePubkeyPolicy,
    TokenError,
    TokenScope,
    ZeroBalancePolicy,
    base58_encode,
    decode_mint_supply,
    decode_token_account,
    encode_account_payload,
    encode_mint_account,
    encode_token_account,
    parse_account_states,
    reconcile_mint,
)

MINT = base58_encode(bytes(range(32)))
OTHER_MINT = base58_encode(bytes(range(1, 33)))


def scope(
    *,
    zero_balance: ZeroBalancePolicy = ZeroBalancePolicy.INCLUDE,
    duplicates: DuplicatePubkeyPolicy = DuplicatePubkeyPolicy.REJECT,
    states: tuple[AccountState, ...] = (AccountState.INITIALIZED, AccountState.FROZEN),
) -> TokenScope:
    return TokenScope(
        program_id=LEGACY_TOKEN_PROGRAM_ID,
        account_size=165,
        mint_offset=0,
        amount_offset=64,
        state_offset=108,
        supply_offset=36,
        included_account_states=states,
        zero_balance_policy=zero_balance,
        duplicate_pubkey_policy=duplicates,
    )


def account(
    pubkey: str,
    amount: int,
    *,
    state: AccountState = AccountState.INITIALIZED,
    mint: str = MINT,
    token_scope: TokenScope | None = None,
) -> dict[str, object]:
    resolved = token_scope or scope()
    data = encode_token_account(
        mint=mint, owner=pubkey, amount=amount, state=state, scope=resolved
    )
    return {
        "pubkey": pubkey,
        "account": encode_account_payload(data, owner=resolved.program_id),
    }


class LayoutTests(unittest.TestCase):
    def test_legacy_account_layout_round_trips(self) -> None:
        resolved = scope()
        data = encode_token_account(
            mint=MINT,
            owner="owner",
            amount=1_234_567,
            state=AccountState.FROZEN,
            scope=resolved,
        )

        record = decode_token_account(
            "pubkey-1",
            encode_account_payload(data, owner=resolved.program_id)["data"],
            scope=resolved,
            encoded_mint=MINT,
        )

        self.assertEqual(record.amount, 1_234_567)
        self.assertIs(record.state, AccountState.FROZEN)
        self.assertEqual(record.mint, MINT)

    def test_a_wrongly_sized_account_is_refused(self) -> None:
        resolved = scope()
        with self.assertRaisesRegex(TokenError, "165"):
            decode_token_account(
                "pubkey-1",
                encode_account_payload(b"\x00" * 164, owner=resolved.program_id)["data"],
                scope=resolved,
                encoded_mint=MINT,
            )

    def test_an_account_of_another_mint_is_refused(self) -> None:
        resolved = scope()
        data = encode_token_account(
            mint=OTHER_MINT,
            owner="owner",
            amount=1,
            state=AccountState.INITIALIZED,
            scope=resolved,
        )

        with self.assertRaisesRegex(TokenError, "not the audited mint"):
            decode_token_account(
                "pubkey-1",
                encode_account_payload(data, owner=resolved.program_id)["data"],
                scope=resolved,
                encoded_mint=MINT,
            )

    def test_mint_supply_is_read_from_the_configured_offset(self) -> None:
        resolved = scope()
        payload = encode_account_payload(
            encode_mint_account(supply=987_654_321, scope=resolved),
            owner=resolved.program_id,
        )

        self.assertEqual(decode_mint_supply(payload["data"], scope=resolved), 987_654_321)

    def test_account_state_names_are_validated(self) -> None:
        self.assertEqual(
            parse_account_states(["initialized", "frozen"]),
            (AccountState.INITIALIZED, AccountState.FROZEN),
        )
        with self.assertRaises(TokenError):
            parse_account_states(["initialised"])
        with self.assertRaisesRegex(TokenError, "twice"):
            parse_account_states(["frozen", "frozen"])


class ReconciliationTests(unittest.TestCase):
    def _reconcile(self, accounts, supply, *, token_scope=None, context_slot=500):
        resolved = token_scope or scope()
        return reconcile_mint(
            mint=MINT,
            pinned_slot=500,
            scope=resolved,
            program_accounts=accounts,
            mint_account=encode_account_payload(
                encode_mint_account(supply=supply, scope=resolved),
                owner=resolved.program_id,
            ),
            context_slot=context_slot,
        )

    def test_a_complete_enumeration_reconciles_to_zero(self) -> None:
        result = self._reconcile(
            [account("a", 100), account("b", 250), account("c", 0)], 350
        )

        self.assertEqual(result.enumerated_total, 350)
        self.assertEqual(result.mint_supply, 350)
        self.assertEqual(result.signed_difference, 0)
        self.assertTrue(result.reconciled)
        self.assertTrue(result.exact_context)

    def test_a_truncated_enumeration_under_reports_by_exactly_the_dropped_balance(
        self,
    ) -> None:
        result = self._reconcile([account("a", 100), account("b", 250)], 350 + 4_242)

        self.assertEqual(result.signed_difference, -4_242)
        self.assertFalse(result.reconciled)

    def test_an_inflated_enumeration_over_reports_with_a_positive_difference(self) -> None:
        result = self._reconcile([account("a", 100), account("b", 250)], 300)

        self.assertEqual(result.signed_difference, 50)

    def test_zero_balance_policy_changes_the_included_population_not_the_total(
        self,
    ) -> None:
        excluding = scope(zero_balance=ZeroBalancePolicy.EXCLUDE)

        included = self._reconcile([account("a", 10), account("b", 0)], 10)
        excluded = self._reconcile(
            [
                account("a", 10, token_scope=excluding),
                account("b", 0, token_scope=excluding),
            ],
            10,
            token_scope=excluding,
        )

        self.assertEqual(included.included_accounts, 2)
        self.assertEqual(excluded.included_accounts, 1)
        self.assertEqual(included.enumerated_total, excluded.enumerated_total)
        self.assertEqual(excluded.excluded_accounts, 1)

    def test_an_excluded_state_is_not_counted(self) -> None:
        only_initialized = scope(states=(AccountState.INITIALIZED,))

        result = self._reconcile(
            [
                account("a", 10, token_scope=only_initialized),
                account(
                    "b",
                    90,
                    state=AccountState.FROZEN,
                    token_scope=only_initialized,
                ),
            ],
            100,
            token_scope=only_initialized,
        )

        self.assertEqual(result.enumerated_total, 10)
        self.assertEqual(result.excluded_accounts, 1)
        self.assertEqual(result.signed_difference, -90)

    def test_duplicate_pubkey_policy_reject_refuses_rather_than_double_counting(
        self,
    ) -> None:
        with self.assertRaisesRegex(TokenError, "duplicate pubkey"):
            self._reconcile([account("a", 10), account("a", 10)], 10)

    def test_duplicate_pubkey_policy_first_wins_counts_once(self) -> None:
        first_wins = scope(duplicates=DuplicatePubkeyPolicy.FIRST_WINS)

        result = self._reconcile(
            [
                account("a", 10, token_scope=first_wins),
                account("a", 10, token_scope=first_wins),
            ],
            10,
            token_scope=first_wins,
        )

        self.assertEqual(result.enumerated_total, 10)
        self.assertEqual(result.duplicate_pubkeys, ("a",))
        self.assertEqual(result.signed_difference, 0)

    def test_an_inexact_context_slot_is_recorded_as_indeterminate(self) -> None:
        result = self._reconcile([account("a", 10)], 10, context_slot=501)

        self.assertFalse(result.exact_context)
        self.assertFalse(result.reconciled)
        self.assertTrue(
            any("not the pinned slot" in reason for reason in result.indeterminate_reasons)
        )

    def test_a_missing_mint_account_leaves_the_difference_undefined(self) -> None:
        resolved = scope()

        result = reconcile_mint(
            mint=MINT,
            pinned_slot=500,
            scope=resolved,
            program_accounts=[account("a", 10)],
            mint_account=None,
            context_slot=500,
        )

        self.assertIsNone(result.mint_supply)
        self.assertIsNone(result.signed_difference)
        self.assertFalse(result.reconciled)
        self.assertTrue(result.indeterminate_reasons)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
