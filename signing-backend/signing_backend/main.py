"""FastAPI application and HTTP routes."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterator

from fastapi import Depends, FastAPI, Request
from fastapi.responses import Response

from . import service, settlement
from .db import connect, init_db
from .errors import ApiError, api_error_handler
from .idempotency import OpResult, idempotent
from .schemas import (
    AccountCreate,
    AgreementCreate,
    CancelRequest,
    ChallengeRequest,
    DelegateRequest,
    DisbursementRequest,
    ReceiptRegisterRequest,
    ReceivableRegisterRequest,
    RefundRegisterRequest,
    RevokeRequest,
    SendRequest,
    SignatureRequest,
    TransferApplyRequest,
    TransferConfirmRequest,
)


def create_app(database_path: str | Path | None = None) -> FastAPI:
    db_path = Path(database_path or os.environ.get("SIGNING_DB_PATH", "data/signing.db"))
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Initialize schema once. Every request gets its own connection.
    init_conn = connect(db_path)
    try:
        init_db(init_conn)
    finally:
        init_conn.close()

    app = FastAPI(
        title="Multi-party Agreement Signing Backend",
        version="1.0.0",
        description=(
            "Ed25519 challenge signing with stages, delegation chains, "
            "cancellation races, idempotency, and independently verifiable certificates."
        ),
    )
    app.state.db_path = db_path
    app.add_exception_handler(ApiError, api_error_handler)

    def get_db(request: Request) -> Iterator[Any]:
        conn = connect(request.app.state.db_path)
        try:
            yield conn
        finally:
            conn.close()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/accounts")
    def create_account(data: AccountCreate, conn: Any = Depends(get_db)) -> Response:
        def producer(c: Any) -> OpResult:
            status, body = service.create_account_tx(c, data)
            return OpResult(status, body)

        result = idempotent(
            conn,
            "account.create",
            data.operation_id,
            {"body": data.model_dump()},
            producer,
        )
        return result.to_response()

    @app.get("/accounts")
    def list_accounts(conn: Any = Depends(get_db)) -> dict[str, Any]:
        return service.list_accounts(conn)

    @app.post("/agreements")
    def create_agreement(data: AgreementCreate, conn: Any = Depends(get_db)) -> Response:
        result = idempotent(
            conn,
            "agreement.create",
            data.operation_id,
            {"body": data.model_dump()},
            lambda c: OpResult(201, service.create_agreement_tx(c, data)),
        )
        return result.to_response()

    @app.get("/agreements")
    def list_agreements(conn: Any = Depends(get_db)) -> dict[str, Any]:
        rows = conn.execute(
            "SELECT agreement_id, title, status, initiator_account_id, created_at "
            "FROM agreements ORDER BY created_at DESC, rowid DESC"
        ).fetchall()
        return {"agreements": [dict(row) for row in rows]}

    @app.get("/agreements/{agreement_id}")
    def get_agreement(agreement_id: str, conn: Any = Depends(get_db)) -> dict[str, Any]:
        return service.agreement_detail(conn, agreement_id)

    @app.get("/agreements/{agreement_id}/body")
    def get_agreement_body(agreement_id: str, conn: Any = Depends(get_db)) -> Response:
        row = service.get_agreement_or_404(conn, agreement_id)
        return Response(
            content=bytes(row["content"]),
            media_type="application/octet-stream",
            headers={"X-Body-Sha256": f"sha256:{row['content_sha256']}"},
        )

    @app.post("/agreements/{agreement_id}/send")
    def send_agreement(
        agreement_id: str, data: SendRequest, conn: Any = Depends(get_db)
    ) -> Response:
        result = idempotent(
            conn,
            "agreement.send",
            data.operation_id,
            {"agreement_id": agreement_id, "body": data.model_dump()},
            lambda c: OpResult(200, service.send_agreement_tx(c, agreement_id, data)),
        )
        return result.to_response()

    @app.post("/agreements/{agreement_id}/cancellation")
    def cancel_agreement(
        agreement_id: str, data: CancelRequest, conn: Any = Depends(get_db)
    ) -> Response:
        result = idempotent(
            conn,
            "agreement.cancel",
            data.operation_id,
            {"agreement_id": agreement_id, "body": data.model_dump()},
            lambda c: OpResult(200, service.cancel_agreement_tx(c, agreement_id, data)),
        )
        return result.to_response()

    @app.get("/agreements/{agreement_id}/seats/{seat_id}/delegations")
    def get_delegations(
        agreement_id: str,
        seat_id: str,
        conn: Any = Depends(get_db),
    ) -> dict[str, Any]:
        return service.delegation_snapshot(conn, agreement_id, seat_id)

    @app.post("/agreements/{agreement_id}/seats/{seat_id}/delegations")
    def delegate_seat(
        agreement_id: str,
        seat_id: str,
        data: DelegateRequest,
        conn: Any = Depends(get_db),
    ) -> Response:
        result = idempotent(
            conn,
            "seat.delegate",
            data.operation_id,
            {
                "agreement_id": agreement_id,
                "seat_id": seat_id,
                "body": data.model_dump(),
            },
            lambda c: OpResult(
                201, service.delegate_seat_tx(c, agreement_id, seat_id, data)
            ),
        )
        return result.to_response()

    @app.post("/agreements/{agreement_id}/seats/{seat_id}/revocations")
    def revoke_delegation(
        agreement_id: str,
        seat_id: str,
        data: RevokeRequest,
        conn: Any = Depends(get_db),
    ) -> Response:
        result = idempotent(
            conn,
            "seat.revoke",
            data.operation_id,
            {
                "agreement_id": agreement_id,
                "seat_id": seat_id,
                "body": data.model_dump(),
            },
            lambda c: OpResult(
                201, service.revoke_delegation_tx(c, agreement_id, seat_id, data)
            ),
        )
        return result.to_response()

    @app.post("/agreements/{agreement_id}/seats/{seat_id}/challenges")
    def issue_challenge(
        agreement_id: str,
        seat_id: str,
        data: ChallengeRequest,
        conn: Any = Depends(get_db),
    ) -> Response:
        def producer(c: Any) -> OpResult:
            raw, headers = service.issue_challenge_tx(c, agreement_id, seat_id, data)
            return OpResult(
                status_code=201,
                raw_body=raw,
                content_type="application/octet-stream",
                headers=headers,
            )

        result = idempotent(
            conn,
            "challenge.issue",
            data.operation_id,
            {
                "agreement_id": agreement_id,
                "seat_id": seat_id,
                "body": data.model_dump(),
            },
            producer,
        )
        return result.to_response()

    @app.post("/challenges/{challenge_id}/signature")
    def submit_signature(
        challenge_id: str, data: SignatureRequest, conn: Any = Depends(get_db)
    ) -> Response:
        result = idempotent(
            conn,
            "signature.submit",
            data.operation_id,
            {"challenge_id": challenge_id, "body": data.model_dump()},
            lambda c: OpResult(201, service.submit_signature_tx(c, challenge_id, data)),
        )
        return result.to_response()

    @app.get("/agreements/{agreement_id}/certificate")
    def certificate(agreement_id: str, conn: Any = Depends(get_db)) -> dict[str, Any]:
        return service.get_certificate(conn, agreement_id)

    # ------------------------------------------------------------------
    # Receivable settlement (应收款结算)
    # ------------------------------------------------------------------

    @app.post("/receivables")
    def register_receivable(data: ReceivableRegisterRequest, conn: Any = Depends(get_db)) -> Response:
        result = idempotent(
            conn,
            "receivable.register",
            data.operation_id,
            {"body": data.model_dump()},
            lambda c: OpResult(201, settlement.register_receivable_tx(c, data)),
        )
        return result.to_response()

    @app.get("/receivables")
    def list_receivables(conn: Any = Depends(get_db)) -> dict[str, Any]:
        return settlement.list_receivables(conn)

    @app.get("/receivables/{receivable_id}")
    def get_receivable(receivable_id: str, conn: Any = Depends(get_db)) -> dict[str, Any]:
        return settlement.receivable_detail(conn, receivable_id)

    @app.post("/receivables/{receivable_id}/transfers")
    def apply_transfer(
        receivable_id: str, data: TransferApplyRequest, conn: Any = Depends(get_db)
    ) -> Response:
        result = idempotent(
            conn,
            "transfer.apply",
            data.operation_id,
            {"receivable_id": receivable_id, "body": data.model_dump()},
            lambda c: OpResult(201, settlement.apply_transfer_tx(c, receivable_id, data)),
        )
        return result.to_response()

    @app.get("/transfers")
    def list_transfers(
        receivable_id: str | None = None, conn: Any = Depends(get_db)
    ) -> dict[str, Any]:
        return settlement.list_transfers(conn, receivable_id)

    @app.get("/transfers/{transfer_id}")
    def get_transfer(transfer_id: str, conn: Any = Depends(get_db)) -> dict[str, Any]:
        return settlement.transfer_view(conn, transfer_id)

    @app.post("/transfers/{transfer_id}/confirmation")
    def confirm_transfer(
        transfer_id: str, data: TransferConfirmRequest, conn: Any = Depends(get_db)
    ) -> Response:
        result = idempotent(
            conn,
            "transfer.confirm",
            data.operation_id,
            {"transfer_id": transfer_id, "body": data.model_dump()},
            lambda c: settlement.confirm_transfer_tx(c, transfer_id, data),
        )
        return result.to_response()

    @app.post("/receivables/{receivable_id}/receipts")
    def register_receipt(
        receivable_id: str, data: ReceiptRegisterRequest, conn: Any = Depends(get_db)
    ) -> Response:
        result = idempotent(
            conn,
            "receipt.register",
            data.operation_id,
            {"receivable_id": receivable_id, "body": data.model_dump()},
            lambda c: OpResult(201, settlement.register_receipt_tx(c, receivable_id, data)),
        )
        return result.to_response()

    @app.get("/receipts/{receipt_id}")
    def get_receipt(receipt_id: str, conn: Any = Depends(get_db)) -> dict[str, Any]:
        return settlement.receipt_detail(conn, receipt_id)

    @app.post("/receipts/{receipt_id}/refunds")
    def register_refund(
        receipt_id: str, data: RefundRegisterRequest, conn: Any = Depends(get_db)
    ) -> Response:
        result = idempotent(
            conn,
            "refund.register",
            data.operation_id,
            {"receipt_id": receipt_id, "body": data.model_dump()},
            lambda c: OpResult(201, settlement.register_refund_tx(c, receipt_id, data)),
        )
        return result.to_response()

    @app.get("/refunds/{refund_id}")
    def get_refund(refund_id: str, conn: Any = Depends(get_db)) -> dict[str, Any]:
        return settlement.refund_detail(conn, refund_id)

    @app.post("/disbursements")
    def register_disbursement(data: DisbursementRequest, conn: Any = Depends(get_db)) -> Response:
        result = idempotent(
            conn,
            "disbursement.register",
            data.operation_id,
            {"body": data.model_dump()},
            lambda c: OpResult(201, settlement.register_disbursement_tx(c, data)),
        )
        return result.to_response()

    @app.get("/settlement-accounts")
    def list_settlement_accounts(conn: Any = Depends(get_db)) -> dict[str, Any]:
        return settlement.list_settlement_accounts(conn)

    @app.get("/settlement-accounts/{account_id}")
    def get_settlement_account(account_id: str, conn: Any = Depends(get_db)) -> dict[str, Any]:
        return settlement.settlement_account_view(conn, account_id)

    return app


app = create_app()
