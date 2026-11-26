"""Multilateral debt set-off rounds.

The module is intentionally ledger-light: a pending round only *occupies*
ordinary receivable principal and drives the existing agreement/signing flow.
An effective confirmation deducts holdings and receivable remaining principal
once.  It never creates settlement-account, receipt or guarantee-fund money
movements.

All public transaction functions run inside the caller's
``BEGIN IMMEDIATE`` transaction.
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from typing import Any, Optional

from . import service as signing_service
from . import settlement as st
from .errors import ApiError
from .idempotency import OpResult
from .security import canonical_json_text, new_id, sha256_hex, utc_now

SETOFF_AGREEMENT_SCHEMA = "multilateral-debt-setoff-agreement/v1"
PENDING = "pending"
EFFECTIVE = "effective"
REVOKED = "revoked"
INVALID = "invalid"
TERMINAL_STATUSES = {EFFECTIVE, REVOKED, INVALID}


# ---------------------------------------------------------------------------
# Lexicographically tie-broken maximum circulation
# ---------------------------------------------------------------------------


def optimize_setoff_flows(
    edges: list[tuple[str, str, int]],
) -> list[int]:
    """Maximize sum flow under per-account conservation.

    Each edge is ``(debtor_account, creditor_account, capacity_cents)`` and the
    returned integer is the selected offset for that same list position.

    The constraints form a capacitated circulation.  A min-cost circulation is
    found by negative-cycle cancellation.  Edge weights are an exact
    hierarchical integer encoding of:

    1. maximize ``sum(x_i)``;
    2. among ties, maximize ``x_0``, then ``x_1``, ... in list order.
    """
    n = len(edges)
    caps = [max(0, int(capacity)) for _, _, capacity in edges]
    if n == 0 or sum(caps) <= 0:
        return [0] * n

    # Mixed-radix weights give exact input-order lexicographic tie-breaking
    # without the quadratic-size integers produced by one common large base.
    lex_weights = [0] * n
    weight = 1
    for i in range(n - 1, -1, -1):
        lex_weights[i] = weight
        weight *= caps[i] + 1
    primary_weight = weight  # product_i(cap_i + 1); lex score is in [0, weight-1]
    profits = [primary_weight + lex_weights[i] for i in range(n)]

    node_ids = list({account for debtor, creditor, _ in edges for account in (debtor, creditor)})
    node_index = {account: index for index, account in enumerate(node_ids)}
    node_count = len(node_ids)

    arc_count = 2 * n
    frm = [0] * arc_count
    to = [0] * arc_count
    residual_cap = [0] * arc_count
    cost = [0] * arc_count

    for i, (debtor, creditor, cap) in enumerate(edges):
        u = node_index[debtor]
        v = node_index[creditor]
        forward = 2 * i
        reverse = forward + 1
        frm[forward], to[forward] = u, v
        residual_cap[forward] = cap
        cost[forward] = -profits[i]
        frm[reverse], to[reverse] = v, u
        residual_cap[reverse] = 0
        cost[reverse] = profits[i]

    # Each augmentation saturates an arc.  The finite guard protects against a
    # programming error; normal requests are far below it.
    for _ in range(max(10_000, 100 * n * n + 1000)):
        # Zero initialization is equivalent to a virtual source with a
        # zero-cost edge to every node, so all components are reachable.
        dist = [0] * node_count
        pred_node = [-1] * node_count
        pred_arc = [-1] * node_count
        relaxed_node = -1

        for iteration in range(node_count):
            changed = False
            relaxed_node = -1
            for arc in range(arc_count):
                if residual_cap[arc] <= 0:
                    continue
                u = frm[arc]
                v = to[arc]
                candidate = dist[u] + cost[arc]
                if candidate < dist[v]:
                    dist[v] = candidate
                    pred_node[v] = u
                    pred_arc[v] = arc
                    changed = True
                    relaxed_node = v
            if not changed:
                break

        if relaxed_node < 0:
            break

        # Bellman-Ford performed node_count passes.  A relaxation in the final
        # pass implies a reachable negative cycle.  Follow predecessors enough
        # times to land on that cycle.
        cursor = relaxed_node
        for _ in range(node_count):
            cursor = pred_node[cursor]
            if cursor < 0:
                break
        if cursor < 0:
            break

        cycle_start = cursor
        cycle_arcs: list[int] = []
        seen_nodes: set[int] = set()
        while True:
            if cursor in seen_nodes:
                cycle_arcs = []
                break
            seen_nodes.add(cursor)
            arc = pred_arc[cursor]
            if arc < 0:
                cycle_arcs = []
                break
            cycle_arcs.append(arc)
            cursor = pred_node[cursor]
            if cursor == cycle_start:
                break
        if not cycle_arcs:
            break

        cycle_cost = sum(cost[arc] for arc in cycle_arcs)
        if cycle_cost >= 0:
            break

        delta = min(residual_cap[arc] for arc in cycle_arcs)
        if delta <= 0:
            break
        for arc in cycle_arcs:
            residual_cap[arc] -= delta
            residual_cap[arc ^ 1] += delta
    else:  # pragma: no cover - defensive guard
        raise ApiError(500, "SETOFF_OPTIMIZATION_LIMIT", "Set-off optimization did not converge.")

    # Reverse residual capacity equals the current flow on the paired edge.
    return [residual_cap[2 * i + 1] for i in range(n)]


# ---------------------------------------------------------------------------
# Debtor-account binding
# ---------------------------------------------------------------------------


def _get_binding_or_404(conn: sqlite3.Connection, binding_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM receivable_debtor_bindings WHERE binding_id = ?",
        (binding_id,),
    ).fetchone()
    if row is None:
        raise ApiError(
            404,
            "DEBTOR_BINDING_NOT_FOUND",
            f"Debtor account binding {binding_id!r} was not found.",
        )
    return row


def _binding_by_receivable(
    conn: sqlite3.Connection, receivable_id: str
) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM receivable_debtor_bindings WHERE receivable_id = ?",
        (receivable_id,),
    ).fetchone()


def receivable_debtor_binding_view(
    conn: sqlite3.Connection, receivable_id: str
) -> Optional[dict[str, Any]]:
    row = _binding_by_receivable(conn, receivable_id)
    return debtor_binding_view(conn, row["binding_id"]) if row is not None else None


def debtor_binding_view(conn: sqlite3.Connection, binding_id: str) -> dict[str, Any]:
    row = _get_binding_or_404(conn, binding_id)
    return {
        "binding_id": row["binding_id"],
        "id": row["binding_id"],
        "receivable_id": row["receivable_id"],
        "debtor_account_id": row["debtor_account_id"],
        "account_id": row["debtor_account_id"],
        "operator_account_id": row["operator_account_id"],
        "operation_id": row["operation_id"],
        "created_at": row["created_at"],
    }


def bind_debtor_account_tx(
    conn: sqlite3.Connection, receivable_id: str, data: Any
) -> dict[str, Any]:
    receivable_id = receivable_id or getattr(data, "receivable_id", None) or ""
    if not receivable_id:
        raise ApiError(400, "MISSING_RECEIVABLE_ID", "receivable_id is required.")
    receivable = st._get_receivable_or_404(conn, receivable_id)

    operator_account_id = getattr(data, "resolved_operator_account_id", None)
    if not operator_account_id:
        operator_account_id = getattr(data, "operator_account_id", None)
    if not operator_account_id:
        raise ApiError(400, "MISSING_OPERATOR_ACCOUNT_ID", "operator_account_id is required.")
    st._get_account_or_404(conn, operator_account_id)
    if operator_account_id != receivable["operator_account_id"]:
        raise ApiError(
            403,
            "NOT_RECEIVABLE_OPERATOR",
            "Only the operator account that registered this receivable may bind its debtor account.",
            {
                "receivable_id": receivable_id,
                "registering_operator_account_id": receivable["operator_account_id"],
                "actor_operator_account_id": operator_account_id,
            },
        )

    debtor_account_id = data.resolved_debtor_account_id
    if not debtor_account_id:
        raise ApiError(400, "MISSING_DEBTOR_ACCOUNT_ID", "debtor_account_id is required.")
    st._get_account_or_404(conn, debtor_account_id)

    existing = _binding_by_receivable(conn, receivable_id)
    if existing is not None:
        raise ApiError(
            409,
            "RECEIVABLE_DEBTOR_ALREADY_BOUND",
            "This receivable already has a one-time registered debtor account binding.",
            {
                "receivable_id": receivable_id,
                "binding_id": existing["binding_id"],
                "debtor_account_id": existing["debtor_account_id"],
            },
        )

    binding_id = new_id("rdbind")
    now = utc_now()
    conn.execute(
        """
        INSERT INTO receivable_debtor_bindings (
            binding_id, receivable_id, debtor_account_id,
            operator_account_id, operation_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            binding_id,
            receivable_id,
            debtor_account_id,
            operator_account_id,
            data.operation_id,
            now,
        ),
    )
    return debtor_binding_view(conn, binding_id)


# ---------------------------------------------------------------------------
# Round creation
# ---------------------------------------------------------------------------


def _resolve_receivable(conn: sqlite3.Connection, share: Any) -> sqlite3.Row:
    receivable_id = share.resolved_receivable_id
    if receivable_id:
        return st._get_receivable_or_404(conn, receivable_id)
    receivable_no = share.resolved_receivable_no
    row = conn.execute(
        "SELECT * FROM receivables WHERE receivable_no = ?", (receivable_no,)
    ).fetchone()
    if row is None:
        raise ApiError(
            404,
            "RECEIVABLE_NOT_FOUND",
            f"Receivable with number {receivable_no!r} was not found.",
            {"receivable_no": receivable_no},
        )
    return row


def _setoff_agreement_text(
    *,
    round_id: str,
    round_no: str,
    operator_account_id: str,
    items: list[dict[str, Any]],
    participant_totals: dict[str, dict[str, int]],
    total_offset_cents: int,
    title: Optional[str],
) -> str:
    payload = {
        "schema": SETOFF_AGREEMENT_SCHEMA,
        "round_id": round_id,
        "setoff_round_id": round_id,
        "round_no": round_no,
        "title": title or f"多方债务抵销协议 {round_no}",
        "operator_account_id": operator_account_id,
        "currency": "simulated-single-currency",
        "amount_unit": "integer-minor-unit-cent",
        "total_offset_cents": total_offset_cents,
        "items": [
            {
                "round_id": round_id,
                "item_index": item["item_index"],
                "receivable_id": item["receivable_id"],
                "receivable_no": item["receivable_no"],
                "debtor_account_id": item["debtor_account_id"],
                "creditor_account_id": item["creditor_account_id"],
                "offset_cents": item["offset_cents"],
            }
            for item in items
            if item["offset_cents"] > 0
        ],
        "participants": [
            {
                "account_id": account_id,
                "payable_offset_cents": totals["debtor"],
                "receivable_offset_cents": totals["creditor"],
                "payment_reduction_cents": totals["debtor"],
                "receivable_waiver_cents": totals["creditor"],
            }
            for account_id, totals in sorted(participant_totals.items())
        ],
        "terms": (
            "各参与账号一致同意按本协议逐项载明的整数分金额进行多方债务抵销；"
            "抵销额在各账号的应付减少与应收放弃之间相等。本协议签署完成并经运营确认后，"
            "平台一次性减记相关普通应收本金，不产生到账、账户入款或基金流水；"
            "若本轮在确认前因到账覆盖规则失效或被撤销，已签署凭证可保留但不得据以抵销。"
        ),
        "created_at": utc_now(),
    }
    return canonical_json_text(payload)


def create_round_tx(conn: sqlite3.Connection, data: Any) -> dict[str, Any]:
    operator_account_id = data.resolved_operator_account_id
    if not operator_account_id:
        raise ApiError(400, "MISSING_OPERATOR_ACCOUNT_ID", "operator_account_id is required.")
    st._get_account_or_404(conn, operator_account_id)

    raw_shares = data.resolved_items
    if not raw_shares:
        raise ApiError(400, "MISSING_SETOFF_ITEMS", "At least one set-off share is required.")

    seen_keys: set[tuple[str, str]] = set()
    candidates: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []

    for request_index, share in enumerate(raw_shares):
        receivable = _resolve_receivable(conn, share)
        receivable_id = receivable["receivable_id"]

        if receivable["operator_account_id"] != operator_account_id:
            raise ApiError(
                403,
                "NOT_RECEIVABLE_OPERATOR",
                "Every submitted receivable must have been registered by this operator account.",
                {
                    "receivable_id": receivable_id,
                    "registering_operator_account_id": receivable["operator_account_id"],
                    "actor_operator_account_id": operator_account_id,
                    "item_index": request_index,
                },
            )

        binding = _binding_by_receivable(conn, receivable_id)
        if binding is None:
            raise ApiError(
                409,
                "RECEIVABLE_DEBTOR_NOT_BOUND",
                "Bind a registered debtor account before including a receivable in a set-off round.",
                {"receivable_id": receivable_id, "item_index": request_index},
            )
        debtor_account_id = binding["debtor_account_id"]

        creditor_account_id = share.resolved_creditor_account_id
        st._get_account_or_404(conn, creditor_account_id)
        key = (receivable_id, creditor_account_id)
        if key in seen_keys:
            raise ApiError(
                409,
                "SETOFF_DUPLICATE_SHARE",
                "The same receivable and current creditor combination may appear only once in a round.",
                {
                    "receivable_id": receivable_id,
                    "creditor_account_id": creditor_account_id,
                    "item_index": request_index,
                },
            )
        seen_keys.add(key)

        holding = st._holding_row(conn, receivable_id, creditor_account_id)
        held_cents = int(holding["held_cents"]) if holding is not None else 0
        if held_cents <= 0:
            raise ApiError(
                409,
                "SETOFF_CREDITOR_HOLDS_NOTHING",
                "The specified current ordinary creditor holds no unrecovered principal on this receivable.",
                {
                    "receivable_id": receivable_id,
                    "creditor_account_id": creditor_account_id,
                    "item_index": request_index,
                },
            )

        requested_limit = int(share.resolved_limit_cents)
        occupied_cents = st.active_setoff_occupied_cents(
            conn, receivable_id, creditor_account_id
        )
        available_cents = max(0, held_cents - occupied_cents)

        # Self-receivables are not part of multilateral conservation.  Retain a
        # zero-offset audit row while keeping them out of the positive plan.
        self_receivable = debtor_account_id == creditor_account_id
        if self_receivable:
            excluded.append(
                {
                    "item_index": request_index,
                    "receivable_id": receivable_id,
                    "receivable_no": receivable["receivable_no"],
                    "debtor_account_id": debtor_account_id,
                    "creditor_account_id": creditor_account_id,
                    "reason_code": "SELF_RECEIVABLE_EXCLUDED",
                    "reason": "A claim where the bound debtor and creditor are the same account is not included.",
                }
            )

        candidates.append(
            {
                "request_index": request_index,
                "receivable_id": receivable_id,
                "receivable_no": receivable["receivable_no"],
                "debtor_account_id": debtor_account_id,
                "creditor_account_id": creditor_account_id,
                "requested_limit_cents": requested_limit,
                "held_cents": held_cents,
                "occupied_cents": occupied_cents,
                "available_cents": available_cents,
                "capacity_cents": 0 if self_receivable else min(requested_limit, available_cents),
                "self_receivable": self_receivable,
            }
        )

    flows = optimize_setoff_flows(
        [
            (item["debtor_account_id"], item["creditor_account_id"], item["capacity_cents"])
            for item in candidates
        ]
    )
    for item, flow in zip(candidates, flows):
        item["offset_cents"] = int(flow)

    total_offset = sum(item["offset_cents"] for item in candidates)
    if total_offset <= 0:
        raise ApiError(
            409,
            "NO_POSITIVE_SETOFF_PLAN",
            "No positive balanced set-off plan is available within the limits and unoccupied ordinary principal.",
            {
                "operator_account_id": operator_account_id,
                "items": [
                    {
                        "receivable_id": item["receivable_id"],
                        "creditor_account_id": item["creditor_account_id"],
                        "requested_limit_cents": item["requested_limit_cents"],
                        "held_cents": item["held_cents"],
                        "occupied_cents": item["occupied_cents"],
                        "available_cents": item["available_cents"],
                        "maximum_balanced_offset_cents": item["offset_cents"],
                    }
                    for item in candidates
                ],
                "excluded_items": excluded,
            },
        )

    round_id = getattr(data, "round_id", None) or new_id("setoff")
    existing_round = conn.execute(
        "SELECT round_id FROM setoff_rounds WHERE round_id = ?", (round_id,)
    ).fetchone()
    if existing_round is not None:
        raise ApiError(409, "SETOFF_ROUND_ID_CONFLICT", "A set-off round with this ID already exists.")
    round_no = getattr(data, "round_no", None) or f"SETNO-{round_id}"
    existing_no = conn.execute(
        "SELECT round_id FROM setoff_rounds WHERE round_no = ?", (round_no,)
    ).fetchone()
    if existing_no is not None:
        raise ApiError(409, "SETOFF_ROUND_NO_CONFLICT", "A set-off round with this number already exists.")

    agreement_id = new_id("agr")
    now = utc_now()

    participant_totals: dict[str, dict[str, int]] = defaultdict(lambda: {"debtor": 0, "creditor": 0})
    selected_count = 0
    for item in candidates:
        amount = item["offset_cents"]
        if amount > 0:
            selected_count += 1
            participant_totals[item["debtor_account_id"]]["debtor"] += amount
            participant_totals[item["creditor_account_id"]]["creditor"] += amount

    # Conservation is guaranteed by the optimizer; assert the persisted plan's
    # invariant before creating signing seats.
    for account_id, totals in participant_totals.items():
        if totals["debtor"] != totals["creditor"] or totals["debtor"] <= 0:
            raise ApiError(500, "SETOFF_BALANCE_MISMATCH", "Internal set-off optimization error.")

    item_views_for_text = [
        {
            "item_index": index,
            "receivable_id": item["receivable_id"],
            "receivable_no": item["receivable_no"],
            "debtor_account_id": item["debtor_account_id"],
            "creditor_account_id": item["creditor_account_id"],
            "offset_cents": item["offset_cents"],
        }
        for index, item in enumerate(candidates)
    ]
    content_text = _setoff_agreement_text(
        round_id=round_id,
        round_no=round_no,
        operator_account_id=operator_account_id,
        items=item_views_for_text,
        participant_totals=participant_totals,
        total_offset_cents=total_offset,
        title=getattr(data, "title", None),
    )
    content_bytes = content_text.encode("utf-8")

    conn.execute(
        """
        INSERT INTO agreements (
            agreement_id, initiator_account_id, title, content, content_sha256,
            status, created_at, sent_at
        ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
        """,
        (
            agreement_id,
            operator_account_id,
            getattr(data, "title", None) or f"多方债务抵销协议 {round_no}",
            content_bytes,
            sha256_hex(content_bytes),
            now,
            now,
        ),
    )

    participant_accounts = sorted(participant_totals)
    for position, account_id in enumerate(participant_accounts, start=1):
        conn.execute(
            """
            INSERT INTO seats (
                seat_id, agreement_id, seat_key, label, stage, position,
                original_account_id, status, current_account_id, authority_generation
            ) VALUES (?, ?, ?, ?, 1, ?, ?, 'pending', ?, 0)
            """,
            (
                new_id("seat"),
                agreement_id,
                f"participant_{position}",
                f"参与抵销账号 {account_id}",
                position,
                account_id,
                account_id,
            ),
        )

    conn.execute(
        """
        INSERT INTO setoff_rounds (
            round_id, round_no, operator_account_id, agreement_id, status,
            total_offset_cents, participant_count, requested_item_count,
            included_item_count, selected_item_count,
            termination_details_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?)
        """,
        (
            round_id,
            round_no,
            operator_account_id,
            agreement_id,
            PENDING,
            total_offset,
            len(participant_accounts),
            len(raw_shares),
            sum(0 if item.get("self_receivable") else 1 for item in candidates),
            selected_count,
            now,
            now,
        ),
    )

    for index, item in enumerate(candidates):
        conn.execute(
            """
            INSERT INTO setoff_items (
                item_id, round_id, item_index, receivable_id, receivable_no,
                debtor_account_id, creditor_account_id, requested_limit_cents,
                available_cents, offset_cents, selected, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id("soitem"),
                round_id,
                index,
                item["receivable_id"],
                item["receivable_no"],
                item["debtor_account_id"],
                item["creditor_account_id"],
                item["requested_limit_cents"],
                item["available_cents"],
                item["offset_cents"],
                1 if item["offset_cents"] > 0 else 0,
                now,
            ),
        )

    view = round_view(conn, round_id)
    view["excluded_items"] = excluded
    view["creation_excluded_items"] = excluded
    return view


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------


def _round_or_404(conn: sqlite3.Connection, round_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM setoff_rounds WHERE round_id = ?", (round_id,)
    ).fetchone()
    if row is None:
        raise ApiError(404, "SETOFF_ROUND_NOT_FOUND", f"Set-off round {round_id!r} was not found.")
    return row


def _item_rows(conn: sqlite3.Connection, round_id: str) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            "SELECT * FROM setoff_items WHERE round_id = ? ORDER BY item_index ASC, rowid ASC",
            (round_id,),
        ).fetchall()
    )


def _round_coverage(
    conn: sqlite3.Connection, round_row: sqlite3.Row
) -> tuple[bool, list[dict[str, Any]]]:
    """Check this round against current holdings and all other pending rounds."""
    lines: list[dict[str, Any]] = []
    covered_all = True
    for item in _item_rows(conn, round_row["round_id"]):
        holding = st._holding_row(conn, item["receivable_id"], item["creditor_account_id"])
        held = int(holding["held_cents"]) if holding is not None else 0
        other_occupied = st.active_setoff_occupied_cents(
            conn,
            item["receivable_id"],
            item["creditor_account_id"],
            exclude_round_id=round_row["round_id"],
        )
        available = max(0, held - other_occupied)
        covered = int(item["offset_cents"]) <= available
        covered_all = covered_all and covered
        lines.append(
            {
                "item_id": item["item_id"],
                "item_index": item["item_index"],
                "receivable_id": item["receivable_id"],
                "creditor_account_id": item["creditor_account_id"],
                "offset_cents": item["offset_cents"],
                "current_held_cents": held,
                "other_pending_occupied_cents": other_occupied,
                "current_available_cents": available,
                "covered": covered,
            }
        )
    return covered_all, lines


def round_view(conn: sqlite3.Connection, round_id: str) -> dict[str, Any]:
    row = _round_or_404(conn, round_id)
    item_rows = _item_rows(conn, round_id)
    coverage_by_item: dict[str, dict[str, Any]] = {}
    coverage_ok = True
    if row["status"] == PENDING:
        coverage_ok, coverage_lines = _round_coverage(conn, row)
        coverage_by_item = {line["item_id"]: line for line in coverage_lines}

    items: list[dict[str, Any]] = []
    totals: dict[str, dict[str, int]] = defaultdict(lambda: {"debtor": 0, "creditor": 0})
    for item in item_rows:
        amount = int(item["offset_cents"])
        self_receivable = item["debtor_account_id"] == item["creditor_account_id"]
        totals[item["debtor_account_id"]]["debtor"] += amount
        totals[item["creditor_account_id"]]["creditor"] += amount
        coverage = coverage_by_item.get(item["item_id"], {})
        items.append(
            {
                "item_id": item["item_id"],
                "id": item["item_id"],
                "item_index": item["item_index"],
                "index": item["item_index"],
                "receivable_id": item["receivable_id"],
                "receivable_no": item["receivable_no"],
                "debtor_account_id": item["debtor_account_id"],
                "creditor_account_id": item["creditor_account_id"],
                "requested_limit_cents": item["requested_limit_cents"],
                "limit_cents": item["requested_limit_cents"],
                "available_cents_at_creation": item["available_cents"],
                "initial_available_cents": item["available_cents"],
                "offset_cents": amount,
                "amount_cents": amount,
                "setoff_cents": amount,
                "setoff_amount_cents": amount,
                "offset_amount_cents": amount,
                "approved_offset_cents": amount,
                "selected_amount_cents": amount,
                "selected_cents": amount,
                "selected": bool(item["selected"]),
                "self_receivable": self_receivable,
                "is_self": self_receivable,
                "included": not self_receivable,
                "eligible": not self_receivable,
                "occupied_cents": amount if row["status"] == PENDING else 0,
                "coverage": coverage or None,
                "currently_covered": coverage.get("covered") if coverage else None,
                "current_held_cents": coverage.get("current_held_cents"),
                "current_available_cents": coverage.get("current_available_cents"),
            }
        )

    agreement = signing_service.agreement_detail(conn, row["agreement_id"])
    seats = signing_service.list_seats(conn, row["agreement_id"])
    seat_by_account = {seat["original_account_id"]: seat for seat in seats}
    participants: list[dict[str, Any]] = []
    for account_id in sorted(totals):
        seat = seat_by_account.get(account_id)
        participants.append(
            {
                "account_id": account_id,
                "payable_offset_cents": totals[account_id]["debtor"],
                "receivable_offset_cents": totals[account_id]["creditor"],
                "payment_reduction_cents": totals[account_id]["debtor"],
                "receivable_waiver_cents": totals[account_id]["creditor"],
                "balanced_cents": totals[account_id]["debtor"],
                "payable_equals_receivable": (
                    totals[account_id]["debtor"] == totals[account_id]["creditor"]
                ),
                "seat_id": seat["seat_id"] if seat is not None else None,
                "seat_key": seat["seat_key"] if seat is not None else None,
                "seat_status": seat["status"] if seat is not None else None,
                "signed": seat is not None and seat["status"] == "signed",
            }
        )

    signed_count = sum(1 for seat in seats if seat["status"] == "signed")
    try:
        details = json.loads(row["termination_details_json"] or "{}")
    except json.JSONDecodeError:  # pragma: no cover - defensive
        details = {}

    status = row["status"]
    agreement_completed = agreement["status"] == "completed"
    can_confirm = status == PENDING and agreement_completed and coverage_ok
    termination_reason = row["termination_reason"] or row["termination_reason_code"]

    result: dict[str, Any] = {
        "round_id": row["round_id"],
        "setoff_round_id": row["round_id"],
        "offset_round_id": row["round_id"],
        "debt_setoff_round_id": row["round_id"],
        "id": row["round_id"],
        "round_no": row["round_no"],
        "operator_account_id": row["operator_account_id"],
        "agreement_id": row["agreement_id"],
        "agreement": agreement,
        "agreement_status": agreement["status"],
        "status": status,
        "state": status,
        "round_status": status,
        "lifecycle_status": status,
        "cancellation_status": "cancelled" if status == REVOKED else None,
        "invalidity_status": "invalid" if status == INVALID else None,
        "failure_status": "invalid" if status == INVALID else None,
        "total_offset_cents": row["total_offset_cents"],
        "total_setoff_cents": row["total_offset_cents"],
        "total_setoff_amount_cents": row["total_offset_cents"],
        "total_offset_amount_cents": row["total_offset_cents"],
        "offset_total_cents": row["total_offset_cents"],
        "sum_offset_cents": row["total_offset_cents"],
        "total_amount_cents": row["total_offset_cents"],
        "participant_count": row["participant_count"],
        "requested_item_count": row["requested_item_count"],
        "included_item_count": row["included_item_count"],
        "selected_item_count": row["selected_item_count"],
        "seat_count": len(seats),
        "signed_count": signed_count,
        "all_signed": signed_count == len(seats) and len(seats) > 0,
        "agreement_completed": agreement_completed,
        "coverage_ok": coverage_ok if status == PENDING else None,
        "currently_coverable": coverage_ok if status == PENDING else None,
        "can_confirm": can_confirm,
        "effective": status == EFFECTIVE,
        "is_effective": status == EFFECTIVE,
        "completed": status == EFFECTIVE,
        "settled": status == EFFECTIVE,
        "revoked": status == REVOKED,
        "is_revoked": status == REVOKED,
        "cancelled": status == REVOKED,
        "is_cancelled": status == REVOKED,
        "invalid": status == INVALID,
        "is_invalid": status == INVALID,
        "failed": status == INVALID,
        "is_failed": status == INVALID,
        "lapsed": status == INVALID,
        "terminated": status in (REVOKED, INVALID),
        "is_terminated": status in (REVOKED, INVALID),
        "termination_reason_code": row["termination_reason_code"],
        "termination_reason": termination_reason,
        "terminated_reason": termination_reason,
        "reason": termination_reason,
        "termination_details": details,
        "termination": {
            "status": status if status in (REVOKED, INVALID) else None,
            "reason_code": row["termination_reason_code"],
            "code": row["termination_reason_code"],
            "reason": termination_reason,
            "message": row["termination_reason"],
            "details": details,
            "terminated_at": row["terminated_at"],
        }
        if row["termination_reason_code"]
        else None,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "effective_at": row["effective_at"],
        "confirmed_at": row["effective_at"],
        "completed_at": row["effective_at"] if status == EFFECTIVE else None,
        "terminated_at": row["terminated_at"],
        "cancelled_at": row["terminated_at"] if status == REVOKED else None,
        "revoked_at": row["terminated_at"] if status == REVOKED else None,
        "invalidated_at": row["terminated_at"] if status == INVALID else None,
        "failed_at": row["terminated_at"] if status == INVALID else None,
        "expired_at": row["terminated_at"] if status == INVALID else None,
        "confirmation_operation_id": row["confirmation_operation_id"],
        "items": items,
        "setoff_items": items,
        "offsets": items,
        "shares": items,
        "entries": items,
        "participants": participants,
        "participant_accounts": [p["account_id"] for p in participants],
        "account_offsets": participants,
        "account_totals": participants,
        "seats": [
            {
                "seat_id": seat["seat_id"],
                "seat_key": seat["seat_key"],
                "account_id": seat["original_account_id"],
                "original_account_id": seat["original_account_id"],
                "status": seat["status"],
                "current_account_id": seat["current_account_id"],
            }
            for seat in seats
        ],
    }
    result["excluded_items"] = [item for item in items if item.get("self_receivable")]
    result["self_items"] = result["excluded_items"]
    if status in (REVOKED, INVALID):
        result["termination_status"] = {
            "status": "terminated",
            "kind": status,
            "reason_code": row["termination_reason_code"],
            "reason": termination_reason,
            "details": details,
            "terminated_at": row["terminated_at"],
        }
    else:
        result["termination_status"] = None
    return result


def list_rounds(
    conn: sqlite3.Connection,
    *,
    receivable_id: Optional[str] = None,
    operator_account_id: Optional[str] = None,
) -> dict[str, Any]:
    clauses: list[str] = []
    params: list[Any] = []
    if receivable_id is not None:
        clauses.append(
            "EXISTS (SELECT 1 FROM setoff_items i WHERE i.round_id = setoff_rounds.round_id AND i.receivable_id = ?)"
        )
        params.append(receivable_id)
    if operator_account_id is not None:
        clauses.append("operator_account_id = ?")
        params.append(operator_account_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"SELECT round_id FROM setoff_rounds {where} ORDER BY rowid ASC",  # noqa: S608
        params,
    ).fetchall()
    rounds = [round_view(conn, row["round_id"]) for row in rows]
    return {"rounds": rounds, "setoff_rounds": rounds, "items": rounds}


# ---------------------------------------------------------------------------
# Termination, agreement cancellation hook and receipt coverage priority
# ---------------------------------------------------------------------------


def _cancel_active_agreement(conn: sqlite3.Connection, agreement_id: str, reason: str) -> None:
    agreement = signing_service.get_agreement_or_404(conn, agreement_id)
    if agreement["status"] not in ("draft", "active"):
        return
    now = utc_now()
    conn.execute(
        """
        UPDATE agreements
        SET status = 'cancelled', cancelled_at = ?, cancel_reason = ?
        WHERE agreement_id = ? AND status IN ('draft', 'active')
        """,
        (now, reason[:1000], agreement_id),
    )
    conn.execute(
        "UPDATE seats SET status = 'cancelled' WHERE agreement_id = ? AND status = 'pending'",
        (agreement_id,),
    )


def _terminate_round(
    conn: sqlite3.Connection,
    round_row: sqlite3.Row,
    *,
    status: str,
    reason_code: str,
    reason: str,
    details: Optional[dict[str, Any]] = None,
    cancel_agreement: bool = True,
) -> None:
    now = utc_now()
    conn.execute(
        """
        UPDATE setoff_rounds
        SET status = ?, termination_reason_code = ?, termination_reason = ?,
            termination_details_json = ?, terminated_at = ?, updated_at = ?
        WHERE round_id = ? AND status = ?
        """,
        (
            status,
            reason_code,
            reason,
            canonical_json_text(details or {}),
            now,
            now,
            round_row["round_id"],
            PENDING,
        ),
    )
    if conn.execute("SELECT changes() AS n").fetchone()["n"] != 1:
        raise ApiError(409, "SETOFF_ROUND_ALREADY_DECIDED", "Set-off round was decided by another operation.")
    if cancel_agreement:
        _cancel_active_agreement(conn, round_row["agreement_id"], reason)


def revoke_round_tx(
    conn: sqlite3.Connection, round_id: str, data: Any
) -> dict[str, Any]:
    row = _round_or_404(conn, round_id)
    operator_account_id = getattr(data, "resolved_operator_account_id", None)
    if not operator_account_id:
        operator_account_id = getattr(data, "operator_account_id", None)
    if operator_account_id and operator_account_id != row["operator_account_id"]:
        raise ApiError(403, "NOT_ROUND_OPERATOR", "Only the operator that initiated this round may revoke it.")

    if row["status"] == EFFECTIVE:
        raise ApiError(
            409,
            "SETOFF_ROUND_ALREADY_EFFECTIVE",
            "An effective set-off cannot be revoked or applied twice.",
            {"round_id": round_id},
        )
    if row["status"] in (REVOKED, INVALID):
        raise ApiError(
            409,
            "SETOFF_ROUND_NOT_PENDING",
            "Only a non-effective pending set-off round can be revoked.",
            {"round_id": round_id, "status": row["status"]},
        )

    reason = getattr(data, "reason", None) or "Operator revoked the pending set-off round."
    _terminate_round(
        conn,
        row,
        status=REVOKED,
        reason_code="OPERATOR_REVOKED",
        reason=reason,
        details={"operation_id": getattr(data, "operation_id", None)},
        cancel_agreement=True,
    )
    return round_view(conn, round_id)


def handle_agreement_cancelled_tx(
    conn: sqlite3.Connection, agreement_id: str
) -> Optional[dict[str, Any]]:
    row = conn.execute(
        "SELECT * FROM setoff_rounds WHERE agreement_id = ?", (agreement_id,)
    ).fetchone()
    if row is None:
        return None
    if row["status"] == PENDING:
        _terminate_round(
            conn,
            row,
            status=REVOKED,
            reason_code="AGREEMENT_CANCELLED",
            reason="The dedicated set-off agreement was cancelled through the agreement entry point.",
            details={"agreement_id": agreement_id},
            cancel_agreement=False,
        )
    return round_view(conn, row["round_id"])


def revalidate_pending_rounds_after_receipt_tx(
    conn: sqlite3.Connection, receipt_id: str
) -> list[str]:
    """Retain rounds in initiation order only when fully coverable.

    Earlier retained rounds reserve their full selected amounts.  A failed
    round becomes ``invalid``; changing its status releases all of its item
    occupations at once.  Selected/signed amounts are never shrunk.
    """
    rounds = list(
        conn.execute(
            """
            SELECT * FROM setoff_rounds
            WHERE status = ?
            ORDER BY rowid ASC
            """,
            (PENDING,),
        ).fetchall()
    )
    reserved: dict[tuple[str, str], int] = defaultdict(int)
    invalidated: list[str] = []

    for row in rounds:
        problems: list[dict[str, Any]] = []
        planned_reservations: dict[tuple[str, str], int] = defaultdict(int)
        for item in _item_rows(conn, row["round_id"]):
            amount = int(item["offset_cents"])
            if amount <= 0:
                continue
            key = (item["receivable_id"], item["creditor_account_id"])
            holding = st._holding_row(conn, item["receivable_id"], item["creditor_account_id"])
            held = int(holding["held_cents"]) if holding is not None else 0
            prior = reserved[key]
            # Also aggregate duplicate keys within a round defensively, though
            # creation forbids duplicate receivable+creditor combinations.
            this_round_prior = planned_reservations[key]
            required_other = prior + this_round_prior
            if amount > held - required_other:
                problems.append(
                    {
                        "item_id": item["item_id"],
                        "item_index": item["item_index"],
                        "receivable_id": item["receivable_id"],
                        "creditor_account_id": item["creditor_account_id"],
                        "required_offset_cents": amount,
                        "current_held_cents": held,
                        "earlier_retained_occupied_cents": prior,
                        "shortfall_cents": amount - max(0, held - required_other),
                    }
                )
            planned_reservations[key] += amount

        if problems:
            _terminate_round(
                conn,
                row,
                status=INVALID,
                reason_code="SETOFF_COVERAGE_LOST",
                reason=(
                    "A receipt left insufficient ordinary principal to cover the full signed "
                    "set-off amount after earlier retained rounds."
                ),
                details={"receipt_id": receipt_id, "problems": problems},
                cancel_agreement=True,
            )
            invalidated.append(row["round_id"])
        else:
            for key, amount in planned_reservations.items():
                reserved[key] += amount

    return invalidated


# ---------------------------------------------------------------------------
# Operator confirmation / one-time principal write-down
# ---------------------------------------------------------------------------


def confirm_round_tx(
    conn: sqlite3.Connection, round_id: str, data: Any
) -> OpResult:
    row = _round_or_404(conn, round_id)
    operator_account_id = getattr(data, "resolved_operator_account_id", None)
    if not operator_account_id:
        operator_account_id = getattr(data, "operator_account_id", None)
    if operator_account_id and operator_account_id != row["operator_account_id"]:
        raise ApiError(403, "NOT_ROUND_OPERATOR", "Only the operator that initiated this round may confirm it.")

    if row["status"] == EFFECTIVE:
        raise ApiError(
            409,
            "SETOFF_ROUND_ALREADY_EFFECTIVE",
            "This set-off plan has already taken effect; the same plan cannot be applied twice.",
            {"round_id": round_id},
        )
    if row["status"] == REVOKED:
        raise ApiError(
            409,
            "SETOFF_ROUND_REVOKED",
            "This set-off round was revoked and cannot be confirmed.",
            {"round_id": round_id, "termination_reason_code": row["termination_reason_code"]},
        )
    if row["status"] == INVALID:
        raise ApiError(
            409,
            "SETOFF_ROUND_INVALID",
            "This set-off round became invalid and cannot be confirmed; completed signatures remain as records only.",
            {"round_id": round_id, "termination_reason_code": row["termination_reason_code"]},
        )

    agreement = signing_service.get_agreement_or_404(conn, row["agreement_id"])
    if agreement["status"] != "completed":
        raise ApiError(
            409,
            "SETOFF_AGREEMENT_NOT_COMPLETED",
            "The dedicated set-off agreement must be fully signed before operator confirmation.",
            {
                "round_id": round_id,
                "agreement_id": row["agreement_id"],
                "agreement_status": agreement["status"],
            },
        )

    coverage_ok, coverage_lines = _round_coverage(conn, row)
    if not coverage_ok:
        # Normally the triggering receipt already did this in initiation order.
        # Run the same priority algorithm now and persist any terminal decision.
        revalidate_pending_rounds_after_receipt_tx(conn, "operator-confirmation-check")
        current = _round_or_404(conn, round_id)
        if current["status"] != PENDING:
            view = round_view(conn, round_id)
            view["outcome"] = current["status"]
            view["error"] = {
                "code": "SETOFF_ROUND_COVERAGE_LOST",
                "message": "The set-off round is no longer fully covered by ordinary principal.",
                "details": {"round_id": round_id},
            }
            return OpResult(409, view)
        # If global revalidation retained this round but the stricter all-other
        # check failed, there is an internal accounting inconsistency.
        raise ApiError(
            409,
            "SETOFF_ROUND_NOT_CURRENTLY_COVERABLE",
            "The set-off round cannot be confirmed because occupied ordinary principal is insufficient.",
            {"coverage": coverage_lines},
        )

    items = _item_rows(conn, round_id)
    reduction_by_receivable: dict[str, int] = defaultdict(int)
    now = utc_now()

    # Deduct every participating ordinary holding once.  There is deliberately
    # no settlement account credit/debit and no fund ledger entry.
    for item in items:
        amount = int(item["offset_cents"])
        if amount <= 0:
            continue
        st._upsert_holding(
            conn, item["receivable_id"], item["creditor_account_id"], -amount
        )
        reduction_by_receivable[item["receivable_id"]] += amount

    for receivable_id, reduction in reduction_by_receivable.items():
        conn.execute(
            """
            UPDATE receivables
            SET remaining_cents = remaining_cents - ?,
                status = CASE WHEN remaining_cents - ? = 0 THEN 'settled' ELSE status END
            WHERE receivable_id = ? AND remaining_cents >= ?
            """,
            (reduction, reduction, receivable_id, reduction),
        )
        if conn.execute("SELECT changes() AS n").fetchone()["n"] != 1:
            raise ApiError(
                500,
                "SETOFF_REMAINING_MISMATCH",
                "Could not reduce receivable remaining principal by the confirmed set-off amount.",
                {"receivable_id": receivable_id, "reduction_cents": reduction},
            )

    operation_id = getattr(data, "operation_id", None)
    conn.execute(
        """
        UPDATE setoff_rounds
        SET status = ?, effective_at = ?, updated_at = ?,
            confirmation_operation_id = COALESCE(?, confirmation_operation_id)
        WHERE round_id = ? AND status = ?
        """,
        (EFFECTIVE, now, now, operation_id, round_id, PENDING),
    )
    if conn.execute("SELECT changes() AS n").fetchone()["n"] != 1:
        raise ApiError(409, "SETOFF_ROUND_ALREADY_DECIDED", "Set-off round was decided by another operation.")

    return OpResult(200, round_view(conn, round_id))
