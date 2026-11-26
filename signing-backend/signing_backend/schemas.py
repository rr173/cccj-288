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
