#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ -x "$ROOT/.venv/bin/python" ]] && "$ROOT/.venv/bin/python" -c "import uvicorn" >/dev/null 2>&1; then
  PY="$ROOT/.venv/bin/python"
else
  PY="${PYTHON:-python3}"
fi

mkdir -p "$ROOT/demo-artifacts"
WORKDIR="$(mktemp -d "$ROOT/demo-artifacts/settlement-XXXXXX")"
PORT="$("$PY" - <<'PYPORT'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PYPORT
)"
BASE_URL="http://127.0.0.1:${PORT}"

export SIGNING_DB_PATH="$WORKDIR/settlement.db"
echo "项目目录: $ROOT"
echo "演示产物: $WORKDIR"
echo "数据库:   $SIGNING_DB_PATH"
echo "服务地址: $BASE_URL"

"$PY" -m uvicorn signing_backend.main:app \
  --host 127.0.0.1 --port "$PORT" --log-level warning \
  >"$WORKDIR/server.log" 2>&1 &
SERVER_PID=$!

cleanup() {
  if kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

healthy=0
for _ in $(seq 1 100); do
  if "$PY" - <<'HEALTH' "$BASE_URL" >/dev/null 2>&1
import sys, urllib.request
urllib.request.urlopen(sys.argv[1] + "/health", timeout=1).read()
HEALTH
  then
    healthy=1
    break
  fi
  if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    echo "服务进程已退出，服务器日志：" >&2
    cat "$WORKDIR/server.log" >&2
    exit 1
  fi
  sleep 0.2
done

if [[ "$healthy" != "1" ]]; then
  echo "等待服务健康检查超时，服务器日志：" >&2
  cat "$WORKDIR/server.log" >&2
  exit 1
fi

echo
echo "########## 应收款结算 HTTP 端到端演示 ##########"
if ! "$PY" "$ROOT/scripts/demo_settlement.py" --base-url "$BASE_URL" --workdir "$WORKDIR"; then
  echo "演示失败，服务器日志：" >&2
  tail -200 "$WORKDIR/server.log" >&2
  exit 1
fi

echo
echo "演示完成。服务已停止；数据库、密钥和查询快照保留在：$WORKDIR"
