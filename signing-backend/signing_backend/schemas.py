"""Pydantic request models."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, model_validator


class AccountCreate(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    account_id: str = Field(min_length=1, max_length=128)
    public_key_b64: str = Field(min_length=1)
    display_name: Optional[str] = None


class SeatSpec(BaseModel):
    # Optional stable client-chosen key. Server assigns seat_1, ... when omitted.
    seat_key: Optional[str] = Field(default=None, pattern=r"^[A-Za-z0-9_.:-]{1,100}$")
    label: Optional[str] = None
    original_account_id: str = Field(min_length=1, max_length=128)
    stage: int = Field(ge=1, le=1000)


class AgreementCreate(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    initiator_account_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=300)
    content_text: Optional[str] = None
    content_base64: Optional[str] = None
    seats: list[SeatSpec] = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def exactly_one_content_form(self) -> "AgreementCreate":
        if (self.content_text is None) == (self.content_base64 is None):
            raise ValueError("provide exactly one of content_text or content_base64")
        return self


class SendRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    initiator_account_id: str = Field(min_length=1, max_length=128)


class CancelRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    initiator_account_id: str = Field(min_length=1, max_length=128)
    reason: Optional[str] = Field(default=None, max_length=1000)


class DelegateRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    actor_account_id: str = Field(min_length=1, max_length=128)
    delegatee_account_id: str = Field(min_length=1, max_length=128)


class RevokeRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    initiator_account_id: str = Field(min_length=1, max_length=128)


class ChallengeRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    account_id: str = Field(min_length=1, max_length=128)


class SignatureRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    signature_b64: str = Field(min_length=1)


# ---------------------------------------------------------------------------
# Receivable settlement (应收款结算) request models.
# All amounts are integer minor units (cents / 分); no decimals, no currency.
# ---------------------------------------------------------------------------


class ReceivableRegisterRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    receivable_no: str = Field(min_length=1, max_length=128)
    agreement_id: str = Field(min_length=1, max_length=128)
    operator_account_id: str = Field(min_length=1, max_length=128)
    debtor: str = Field(min_length=1, max_length=300)
    original_creditor_id: str = Field(min_length=1, max_length=128)
    principal_cents: int = Field(gt=0)
    debtor_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    bound_debtor_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)

    @property
    def resolved_debtor_account_id(self) -> Optional[str]:
        return self.debtor_account_id or self.bound_debtor_account_id


class TransferApplyRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    transferor_account_id: str = Field(min_length=1, max_length=128)
    transferee_account_id: str = Field(min_length=1, max_length=128)
    amount_cents: int = Field(gt=0)


class TransferConfirmRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    operator_account_id: str = Field(min_length=1, max_length=128)


class ReceiptRegisterRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    channel_serial_no: str = Field(min_length=1, max_length=200)
    amount_cents: int = Field(gt=0)
    operator_account_id: str = Field(min_length=1, max_length=128)


class RefundRegisterRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    channel_serial_no: str = Field(min_length=1, max_length=200)
    amount_cents: int = Field(gt=0)
    operator_account_id: str = Field(min_length=1, max_length=128)


class DisbursementRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    account_id: str = Field(min_length=1, max_length=128)
    amount_cents: int = Field(gt=0)
    operator_account_id: str = Field(min_length=1, max_length=128)
    note: Optional[str] = Field(default=None, max_length=1000)


# ---------------------------------------------------------------------------
# Guarantee funds / compensation / subrogation request models.
# ---------------------------------------------------------------------------


class GuaranteeFundCreateRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    fund_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    fund_no: Optional[str] = Field(default=None, min_length=1, max_length=128)
    fund_code: Optional[str] = Field(default=None, min_length=1, max_length=128)
    code: Optional[str] = Field(default=None, min_length=1, max_length=128)
    name: Optional[str] = Field(default=None, max_length=300)
    fund_name: Optional[str] = Field(default=None, max_length=300)
    display_name: Optional[str] = Field(default=None, max_length=300)
    operator_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    initial_amount_cents: Optional[int] = Field(default=None, ge=0)
    initial_contribution_cents: Optional[int] = Field(default=None, ge=0)
    opening_balance_cents: Optional[int] = Field(default=None, ge=0)
    balance_cents: Optional[int] = Field(default=None, ge=0)
    amount_cents: Optional[int] = Field(default=None, ge=0)

    @property
    def resolved_name(self) -> Optional[str]:
        return self.name or self.fund_name or self.display_name

    @property
    def resolved_initial_amount_cents(self) -> int:
        for value in (
            self.initial_amount_cents,
            self.initial_contribution_cents,
            self.opening_balance_cents,
            self.balance_cents,
            self.amount_cents,
        ):
            if value is not None:
                return value
        return 0


class FundContributionRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    amount_cents: int = Field(gt=0)
    operator_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    note: Optional[str] = Field(default=None, max_length=1000)


class GuaranteeBindingRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    fund_id: str = Field(min_length=1, max_length=128)
    limit_cents: Optional[int] = Field(default=None, gt=0)
    compensation_limit_cents: Optional[int] = Field(default=None, gt=0)
    limit_amount_cents: Optional[int] = Field(default=None, gt=0)
    operator_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)

    @property
    def resolved_limit_cents(self) -> int:
        # FastAPI/Pydantic validation guarantees one positive value before the
        # route producer runs; the model validator below gives a clean 422.
        return int(
            self.limit_cents
            or self.compensation_limit_cents
            or self.limit_amount_cents
            or 0
        )

    @model_validator(mode="after")
    def require_limit(self) -> "GuaranteeBindingRequest":
        if (
            self.limit_cents is None
            and self.compensation_limit_cents is None
            and self.limit_amount_cents is None
        ):
            raise ValueError("provide limit_cents or compensation_limit_cents")
        return self


class CompensationCreateRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    receivable_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    fund_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    creditor_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    creditor_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    amount_cents: int = Field(gt=0)
    operator_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)

    @property
    def resolved_creditor_account_id(self) -> str:
        return self.creditor_account_id or self.creditor_id or self.account_id or ""

    @model_validator(mode="after")
    def require_creditor(self) -> "CompensationCreateRequest":
        if not self.resolved_creditor_account_id:
            raise ValueError("provide creditor_account_id or account_id")
        return self


# ---------------------------------------------------------------------------
# Bound debtor accounts and multilateral debt set-off request models.
# ---------------------------------------------------------------------------


class DebtorAccountBindingRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    receivable_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    operator_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    operator: Optional[str] = Field(default=None, min_length=1, max_length=128)
    debtor_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    debtor_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    debtor_account: Optional[str] = Field(default=None, min_length=1, max_length=128)
    debtor: Optional[str] = Field(default=None, min_length=1, max_length=128)

    @property
    def resolved_operator_account_id(self) -> Optional[str]:
        return self.operator_account_id or self.operator

    @property
    def resolved_debtor_account_id(self) -> str:
        return (
            self.debtor_account_id
            or self.debtor_id
            or self.account_id
            or self.debtor_account
            or self.debtor
            or ""
        )

    @model_validator(mode="after")
    def require_debtor(self) -> "DebtorAccountBindingRequest":
        if not self.resolved_debtor_account_id:
            raise ValueError("provide debtor_account_id")
        return self


class SetoffShareRequest(BaseModel):
    # Extra caller-specific naming is tolerated; resolution below also checks
    # a few common extra aliases used by alternative HTTP clients.
    model_config = {"extra": "allow"}

    receivable_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    receivable_no: Optional[str] = Field(default=None, min_length=1, max_length=128)
    receivable_number: Optional[str] = Field(default=None, min_length=1, max_length=128)

    creditor_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    current_creditor_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    ordinary_creditor_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    creditor_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    creditor: Optional[str] = Field(default=None, min_length=1, max_length=128)

    limit_cents: Optional[int] = Field(default=None, ge=0)
    positive_limit_cents: Optional[int] = Field(default=None, ge=0)
    amount_limit_cents: Optional[int] = Field(default=None, ge=0)
    max_amount_cents: Optional[int] = Field(default=None, ge=0)
    maximum_cents: Optional[int] = Field(default=None, ge=0)
    max_offset_cents: Optional[int] = Field(default=None, ge=0)
    offset_limit_cents: Optional[int] = Field(default=None, ge=0)
    upper_limit_cents: Optional[int] = Field(default=None, ge=0)
    cap_cents: Optional[int] = Field(default=None, ge=0)
    amount_cents: Optional[int] = Field(default=None, ge=0)
    setoff_limit_cents: Optional[int] = Field(default=None, ge=0)
    maximum_offset_amount_cents: Optional[int] = Field(default=None, ge=0)
    per_share_limit_cents: Optional[int] = Field(default=None, ge=0)
    offset_cents: Optional[int] = Field(default=None, ge=0)
    setoff_cents: Optional[int] = Field(default=None, ge=0)

    def _extra_str(self, *names: str) -> Optional[str]:
        extra = getattr(self, "model_extra", None) or {}
        for name in names:
            value = extra.get(name)
            if isinstance(value, str) and value:
                return value
        return None

    def _extra_int(self, *names: str) -> Optional[int]:
        extra = getattr(self, "model_extra", None) or {}
        for name in names:
            value = extra.get(name)
            if isinstance(value, int) and value >= 0:
                return value
        return None

    @property
    def resolved_receivable_id(self) -> Optional[str]:
        return (
            self.receivable_id
            or self.id
            or self._extra_str("receivable", "receivableId", "receivableID")
        )

    @property
    def resolved_receivable_no(self) -> Optional[str]:
        return (
            self.receivable_no
            or self.receivable_number
            or self._extra_str("receivableNo", "receivable_number", "no")
        )

    @property
    def resolved_creditor_account_id(self) -> str:
        value = (
            self.creditor_account_id
            or self.current_creditor_account_id
            or self.ordinary_creditor_account_id
            or self.creditor_id
            or self.account_id
            or self.creditor
            or self._extra_str(
                "current_creditor_id",
                "ordinary_creditor_id",
                "creditorAccountId",
                "account",
            )
            or ""
        )
        return value

    @property
    def resolved_limit_cents(self) -> int:
        for value in (
            self.limit_cents,
            self.positive_limit_cents,
            self.amount_limit_cents,
            self.max_amount_cents,
            self.maximum_cents,
            self.max_offset_cents,
            self.offset_limit_cents,
            self.upper_limit_cents,
            self.cap_cents,
            self.amount_cents,
            self.setoff_limit_cents,
            self.maximum_offset_amount_cents,
            self.per_share_limit_cents,
            self.offset_cents,
            self.setoff_cents,
            self._extra_int(
                "max",
                "limit",
                "cap",
                "upper_bound_cents",
                "positive_upper_limit_cents",
                "max_amount",
                "maximum_amount_cents",
                "offset_cap_cents",
            ),
        ):
            if value is not None:
                return int(value)
        # Tolerate alternative *_limit_cents / *_cap_cents field names without
        # allowing an unrelated non-negative ID-like value to become the cap.
        extra = getattr(self, "model_extra", None) or {}
        for key, value in extra.items():
            if (
                isinstance(value, int)
                and not isinstance(value, bool)
                and value >= 0
                and (
                    "limit" in key
                    or "cap" in key
                    or "max" in key
                    or "upper" in key
                )
            ):
                return int(value)
        # A missing cap is invalid for a share; the model validator raises.
        return -1

    @model_validator(mode="after")
    def require_share_fields(self) -> "SetoffShareRequest":
        if not self.resolved_receivable_id and not self.resolved_receivable_no:
            raise ValueError("each share requires receivable_id or receivable_no")
        if not self.resolved_creditor_account_id:
            raise ValueError("each share requires a current creditor account")
        if self.resolved_limit_cents < 0:
            raise ValueError("each share requires a non-negative positive limit in cents")
        return self


class SetoffRoundCreateRequest(BaseModel):
    model_config = {"extra": "allow"}

    operation_id: str = Field(min_length=1, max_length=200)
    operator_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    operator: Optional[str] = Field(default=None, min_length=1, max_length=128)
    initiator_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    round_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    round_no: Optional[str] = Field(default=None, min_length=1, max_length=128)
    title: Optional[str] = Field(default=None, max_length=300)
    items: Optional[list[SetoffShareRequest]] = None
    shares: Optional[list[SetoffShareRequest]] = None
    setoff_items: Optional[list[SetoffShareRequest]] = None
    entries: Optional[list[SetoffShareRequest]] = None
    receivable_shares: Optional[list[SetoffShareRequest]] = None
    setoff_shares: Optional[list[SetoffShareRequest]] = None
    share_list: Optional[list[SetoffShareRequest]] = None
    claims: Optional[list[SetoffShareRequest]] = None

    @property
    def resolved_operator_account_id(self) -> str:
        return self.operator_account_id or self.operator or self.initiator_account_id or ""

    @property
    def resolved_items(self) -> list[SetoffShareRequest]:
        for value in (
            self.items,
            self.shares,
            self.setoff_items,
            self.entries,
            self.receivable_shares,
            self.setoff_shares,
            self.share_list,
            self.claims,
        ):
            if value is not None:
                return value
        extra = getattr(self, "model_extra", None) or {}
        for value in extra.values():
            if isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
                return [SetoffShareRequest.model_validate(x) for x in value]
        return []

    @model_validator(mode="after")
    def require_items(self) -> "SetoffRoundCreateRequest":
        if not self.resolved_items:
            raise ValueError("provide at least one set-off share in items or shares")
        return self


class SetoffRoundActionRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    operator_account_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    operator: Optional[str] = Field(default=None, min_length=1, max_length=128)
    reason: Optional[str] = Field(default=None, max_length=1000)

    @property
    def resolved_operator_account_id(self) -> Optional[str]:
        return self.operator_account_id or self.operator


# Common naming aliases for callers/tests that use the domain verbs "fund
# create", "top-up", "binding" or "advance/compensation".
GuaranteeFundCreate = GuaranteeFundCreateRequest
FundCreateRequest = GuaranteeFundCreateRequest
FundContributionCreateRequest = FundContributionRequest
FundTopUpRequest = FundContributionRequest
GuaranteeBindingCreateRequest = GuaranteeBindingRequest
BindingCreateRequest = GuaranteeBindingRequest
CompensationCreate = CompensationCreateRequest
GuaranteeCompensationCreateRequest = CompensationCreateRequest
AdvanceCreateRequest = CompensationCreateRequest

# Set-off naming aliases for callers that omit the Request suffix or use
# Binding/Offset vocabulary.
DebtorBindingCreateRequest = DebtorAccountBindingRequest
DebtorAccountBindingCreateRequest = DebtorAccountBindingRequest
SetoffRoundCreate = SetoffRoundCreateRequest
SetoffCreateRequest = SetoffRoundCreateRequest
OffsetRoundCreateRequest = SetoffRoundCreateRequest
SetoffRoundAction = SetoffRoundActionRequest
SetoffConfirmationRequest = SetoffRoundActionRequest
SetoffRevocationRequest = SetoffRoundActionRequest
DebtOffsetRoundCreateRequest = SetoffRoundCreateRequest
