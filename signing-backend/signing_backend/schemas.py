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
