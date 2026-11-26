# 多人协议正文签署后端

一个用 **Python + FastAPI + SQLite + cryptography(Ed25519)** 实现的多人确认同一份协议正文的签署后端。

它覆盖：

- 发起人准备协议正文、签署席位、每个席位的原责任账号和阶段号；
- 发送后正文与席位冻结，没有任何修改正文/席位的接口；
- 同阶段席位可并行签署，前一阶段全部完成后下一阶段才能取挑战/签署；
- 本机生成 Ed25519 密钥，私钥只留在请求脚本，服务端只保存公钥；
- 当前被授权人可连续委托，但不能形成环；
- 发起人可撤销未完成席位的整条委托链，签署权回到原责任人；
- 委托/撤销会提高席位的 `authority_generation`；旧挑战即使后来又委托回同一账号也永久失效；
- 服务端签发一次性挑战，脚本对 HTTP 返回的**原始字节**做 Ed25519 签名；
- 落签前同时校验阶段、当前资格、委托快照、挑战一次性和签名；
- 保存实际签署人、公钥、签名、挑战字节以及当时完整委托来源/历史；
- 同一账号可受托多个席位，但每个席位的挑战和签名仍逐一绑定，不能一签多席；
- 发起人可取消未完成协议；SQLite `BEGIN IMMEDIATE` 保证“最后签名 vs 取消”只能产生 `completed` 或 `cancelled`；
- `operation_id` 持久化去重：同 ID 同内容返回首次结果，同 ID 换内容拒绝；
- 一个挑战最多产生一条签署事实；
- 重启后状态、凭证和去重记录仍有效；
- 全部席位完成后生成可离线核验的 JSON 签署凭证。

## 目录

```text
signing_backend/
  main.py          # FastAPI HTTP 路由
  service.py       # 阶段、委托、撤销、挑战、落签、取消、凭证核心事务
  db.py            # SQLite schema、连接、BEGIN IMMEDIATE 事务
  idempotency.py   # 持久化 operation_id 去重/重放
  security.py      # canonical JSON、SHA-256、base64、Ed25519 校验
  verifier.py      # 不依赖服务端/数据库的离线凭证核验器
scripts/
  client_lib.py    # 请求侧密钥库和 HTTP 客户端（私钥只在这里读取/签名）
  signctl.py       # 可运行的 keygen/register/sign-challenge/verify CLI
  demo_http.py     # 完整 HTTP 演示
tests/
  test_backend.py  # 阶段、委托、旧挑战、去重、重启、一签一席、正文改版
  test_race.py     # 取消与最后签名的并发竞争
run_demo.sh        # 自动起本机 uvicorn、跑 HTTP 演示、再独立验签
verify_certificate.py
requirements.txt
```

## 快速运行

当前工作区已经创建 `.venv` 并安装依赖。全新环境可用：

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

一键演示：

```bash
./run_demo.sh
```

脚本会：

1. 选择空闲本机端口；
2. 用临时 SQLite 数据库启动 uvicorn；
3. 生成本机 Ed25519 私钥；
4. 走真实 HTTP 流程；
5. 演示两阶段并行签署；
6. 演示连续委托、环拒绝、撤销后再委托回同一账号、旧挑战重放失败；
7. 演示同一 `operation_id` 重试和同一挑战不能产生第二事实；
8. 生成并离线验证凭证；
9. 停止服务并保留产物路径。

运行自动化验证：

```bash
.venv/bin/python -m pytest -q
```

当前包含 9 个测试，其中并发测试会重复多轮“取消 vs 最后签名”。

## 手动启动 HTTP 服务

```bash
export SIGNING_DB_PATH=./data/dev.db
.venv/bin/python -m uvicorn signing_backend.main:app \
  --host 127.0.0.1 --port 18080
```

打开：

- Swagger UI：<http://127.0.0.1:18080/docs>
- 健康检查：<http://127.0.0.1:18080/health>

## 可运行的本机签名脚本

生成密钥（私钥 PEM 权限设为 `0600`，服务端不会接触它）：

```bash
.venv/bin/python scripts/signctl.py \
  --base-url http://127.0.0.1:18080 \
  keygen --keys-dir ./keys --account alice
```

只登记公钥：

```bash
.venv/bin/python scripts/signctl.py \
  --base-url http://127.0.0.1:18080 \
  register --keys-dir ./keys --account alice
```

对某个席位取挑战、对返回的原始字节签名并提交：

```bash
.venv/bin/python scripts/signctl.py \
  --base-url http://127.0.0.1:18080 \
  sign-challenge \
  --keys-dir ./keys \
  --agreement agr_xxx \
  --seat seat_xxx \
  --account alice \
  --operation-id my-signature-operation-1
```

其核心代码等价于：

```python
challenge_response = client.post(challenge_url, json=...)
challenge_id = challenge_response.headers["x-challenge-id"]

# 注意：签名的是 HTTP 响应的精确原始字节，不是重新 JSON 序列化的内容。
signature = private_key.sign(challenge_response.content)

client.post(
    f"/challenges/{challenge_id}/signature",
    json={"operation_id": "...", "signature_b64": base64(signature)},
)
```

## 典型 HTTP 流程

所有写操作都需要请求体中的 `operation_id`。

### 1. 登记公钥

```http
POST /accounts
Content-Type: application/json
```

```json
{
  "operation_id": "register-alice-1",
  "account_id": "alice",
  "public_key_b64": "<raw 32-byte Ed25519 public key, base64>",
  "display_name": "Alice"
}
```

同一 `account_id` 重复提交相同公钥返回首次结果；不同公钥返回 `ACCOUNT_KEY_CONFLICT`。

### 2. 发起人准备协议和席位

```http
POST /agreements
```

```json
{
  "operation_id": "create-agreement-1",
  "initiator_account_id": "initiator-1",
  "title": "两阶段签署协议",
  "content_text": "协议正文原始文本……",
  "seats": [
    {"seat_key": "a1", "original_account_id": "alice", "stage": 1},
    {"seat_key": "b1", "original_account_id": "bob", "stage": 1},
    {"seat_key": "c1", "original_account_id": "carol", "stage": 2}
  ]
}
```

也可以传 `content_base64`，适合任意二进制/文件正文。创建后状态是 `draft`。

### 3. 发送并冻结

```http
POST /agreements/{agreement_id}/send
```

```json
{
  "operation_id": "send-agreement-1",
  "initiator_account_id": "initiator-1"
}
```

发送后状态为 `active`。服务端没有正文更新、席位更新或删除接口；正文 SHA-256 会绑定到每个挑战、签名和凭证。

如果发送后发现正文要改：

1. 发起人调用 `POST /agreements/{id}/cancellation` 取消原件；
2. 用新 `operation_id` 创建新协议和新席位；
3. 所有签署人对新挑战重新签名。

旧签名只绑定旧正文哈希和旧挑战字节，不能当作新正文的确认。测试 `test_body_change_means_cancel_and_new_agreement` 明确验证了这一点。

### 4. 委托和撤销

当前被授权人委托：

```http
GET  /agreements/{agreement_id}/seats/{seat_id}/delegations
POST /agreements/{agreement_id}/seats/{seat_id}/delegations
```

`GET` 返回当前活动链、完整委托/撤销历史和当前 `authority_generation`。

```json
{
  "operation_id": "delegate-1",
  "actor_account_id": "alice",
  "delegatee_account_id": "bob"
}
```

Bob 可以继续委托给 Carol。若 Carol 再委托回 Alice/Bob 等当前链中已有的账号，返回 `DELEGATION_CYCLE`。

发起人撤销整条未完成委托链：

```http
POST /agreements/{agreement_id}/seats/{seat_id}/revocations
```

```json
{
  "operation_id": "revoke-1",
  "initiator_account_id": "initiator-1"
}
```

撤销后 `current_account_id` 恢复为 `original_account_id`，且 `authority_generation + 1`。已经签署的席位返回 `SEAT_NOT_PENDING`，不能转名或事后撤销委托。

### 5. 获取原始字节挑战

```http
POST /agreements/{agreement_id}/seats/{seat_id}/challenges
Accept: application/octet-stream
```

```json
{
  "operation_id": "challenge-op-1",
  "account_id": "carol"
}
```

成功响应：

- HTTP `201`
- `Content-Type: application/octet-stream`
- Header `X-Challenge-Id: chal_...`
- Body 是确定性 canonical JSON 的原始 UTF-8 字节。

挑战中明确包含：

- challenge ID、签发时间、随机 nonce；
- `agreement_id`、标题；
- 正文哈希 `body_sha256`；
- `seat_id/key/stage/original_account_id`；
- 实际签署账号和该账号登记的公钥；
- 签发时完整委托资格快照、活动委托链、全部委托/撤销历史、`authority_generation` 和快照哈希；
- 阶段门快照：所有更低阶段席位及其签名 ID。

### 6. 提交签名

```http
POST /challenges/{challenge_id}/signature
```

```json
{
  "operation_id": "signature-op-1",
  "signature_b64": "<64-byte raw Ed25519 signature, base64>"
}
```

服务端在 `BEGIN IMMEDIATE` 事务内重新检查：

1. 挑战存在且未消费；
2. 协议仍为 `active`；
3. 席位仍为 `pending`；
4. 当前阶段门仍满足；
5. 挑战中的 `authority_generation` 等于席位当前 generation；
6. 挑战账号仍是当前被授权人；
7. 当前委托快照哈希与挑战绑定的资格哈希一致；
8. 公钥仍是登记公钥；
9. Ed25519 密码学验证通过。

因此，仅仅“签名能通过公钥验证”不足以落签；如果挑战发出后发生过委托或撤销，即使后来又委托回同一账号，generation 和快照哈希也已经变化，提交会得到 `AUTHORITY_STALE`。

### 7. 取消

```http
POST /agreements/{agreement_id}/cancellation
```

```json
{
  "operation_id": "cancel-op-1",
  "initiator_account_id": "initiator-1",
  "reason": "正文需要改版"
}
```

未完成协议可取消；未签署席位变为 `cancelled`，已有签名事实保留。全部完成后返回 `AGREEMENT_COMPLETED`。

取消事务和最后签名事务都使用 `BEGIN IMMEDIATE` 串行化：

- 签名先提交：协议 `completed`，取消得到 `AGREEMENT_COMPLETED`，存在凭证和恰好一条席位签名；
- 取消先提交：协议 `cancelled`，签名得到 `AGREEMENT_NOT_ACTIVE`，没有最后一条签名或完成凭证。

## 幂等和重放

每个写接口都以 `(scope, operation_id)` 持久化：

- 请求 canonical hash；
- 首次 HTTP 状态码；
- 响应体或原始挑战字节；
- 自定义响应头。

规则：

- 相同 `operation_id` + 相同规范化请求内容：返回首次状态和响应，不新增事实；
- 相同 `operation_id` + 不同内容：`409 IDEMPOTENCY_REQUEST_CONFLICT`；
- 同一挑战 + 相同签名 + 相同签名 `operation_id`：返回首次签名结果；
- 同一挑战换一个新的 `operation_id` 重放：`409 CHALLENGE_ALREADY_USED`；
- 数据库唯一约束还包括 `signatures.challenge_id UNIQUE` 和 `signatures.seat_id UNIQUE`。

所有状态都在 SQLite 中，没有内存去重表。测试 `test_restart_preserves_state_and_idempotency` 会销毁第一个 app/client、用同一数据库路径创建第二个 app，再验证相同操作 ID 返回原结果、旧挑战不能产生第二事实、凭证仍可验证。

## 独立验签

全部席位签署后：

```http
GET /agreements/{agreement_id}/certificate
```

保存响应 JSON，然后离线验证：

```bash
.venv/bin/python verify_certificate.py \
  /path/to/two-stage-certificate.json \
  --registry /path/to/registry.json \
  --body-file /path/to/agreement-body.txt
```

参数：

- `certificate.json`：服务端生成的凭证，内含正文 base64、公钥、签名、精确挑战字节、委托来源和阶段门；
- `--registry`：可选但推荐，使用 `GET /accounts` 导出的账号公钥注册表，把账号 ID 锚定到服务端登记公钥；
- `--body-file`：可选，用调用方持有的原始文件与凭证内正文做逐字节比较；
- `--write-body out.bin`：只有凭证和签名验证通过时才导出正文；
- `--json`：输出机器可读报告。

验签器会检查：

- 凭证整体哈希；
- 内嵌正文 SHA-256/长度，以及可选外部原文件；
- 每个席位是否完成；
- 每个 Ed25519 公钥对精确 `challenge_b64` 字节和 `signature_b64` 是否有效；
- 挑战是否绑定该协议、正文哈希、席位、阶段、原责任人、实际签署人和公钥；
- 委托链是否从原责任人连续连接到实际签署人；
- 链中是否有环；
- challenge 中的资格哈希是否与保存的完整委托来源一致；
- 如果提供 registry，实际签署人公钥是否为注册表中的公钥，链上账号是否均已登记；
- 第二阶段挑战/签名时，阶段门快照中的低阶段签名 ID 集合是否与凭证一致；
- `stage_summary` 是否与各席位完成状态一致。

不传 `--registry` 时，验签器仍可验证凭证内密钥、签名和委托链自洽，但会明确警告：账号到公钥的身份绑定没有使用可信注册表锚定。这是模拟系统的信任边界：服务端负责公钥登记，真实生产环境应再接入组织身份认证。

仓库中附带了一份演示生成的样例，可立即试跑：

```bash
.venv/bin/python verify_certificate.py \
  examples/sample-certificate.json \
  --registry examples/sample-registry.json \
  --body-file examples/sample-body.txt

.venv/bin/python verify_certificate.py \
  examples/sample-delegation-certificate.json \
  --registry examples/sample-registry.json
```

## 自动化测试说明

```bash
.venv/bin/python -m pytest -q
```

覆盖：

- 两阶段门和完整凭证验证；
- 委托、连续委托、环拒绝、越权委托拒绝；
- 撤销后再委托回同一账号，旧挑战仍 `AUTHORITY_STALE`；
- 已完成席位不能再委托/撤销；
- 同一账号受托两个席位时，一个签名不能用于另一个席位；
- 同一挑战不能产生第二事实；
- operation ID 同内容重放、换内容冲突；
- 取消后正文改版必须创建新协议，旧签名不能验证新正文；
- 重启后状态、幂等和挑战消费状态仍有效；
- 单轮和多轮重复的“取消 vs 最后签名”竞争一致性。

## 生产化前仍需补充的事项

本任务明确要求用本机密钥模拟签署人、不接外部身份系统，因此当前 HTTP 请求中的 `actor_account_id` / `initiator_account_id` 是模拟身份字段，没有加真实登录鉴权。生产化前应增加：

- 用户认证和服务端会话/令牌授权，而不是信任请求体中的账号 ID；
- 更严格的账号公钥注册证明（例如注册时用对应私钥签名注册挑战）；
- HTTPS、限流、审计日志访问控制；
- 挑战过期时间和 nonce 清理策略；
- SQLite 备份或迁移到 PostgreSQL；
- 多 worker 部署时继续依赖数据库事务/唯一约束，而不是进程内锁。
