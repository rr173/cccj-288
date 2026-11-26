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
  settlement.py    # 应收款、本金转让、到账分款、退票冲回、结算账户与划款事务
  setoff.py        # 债务人账号绑定、多方债务抵销优化、占用、签署、失效优先级与确认
  db.py            # SQLite schema、连接、BEGIN IMMEDIATE 事务
  idempotency.py   # 持久化 operation_id 去重/重放
  security.py      # canonical JSON、SHA-256、base64、Ed25519 校验
  verifier.py      # 不依赖服务端/数据库的离线凭证核验器
scripts/
  client_lib.py    # 请求侧密钥库和 HTTP 客户端（私钥只在这里读取/签名）
  signctl.py       # 可运行的 keygen/register/sign-challenge/verify CLI
  demo_http.py     # 完整签署流程 HTTP 演示
  demo_settlement.py  # 应收款结算完整 HTTP 演示
  demo_setoff.py      # 多方债务抵销完整 HTTP 演示
tests/
  test_backend.py  # 阶段、委托、旧挑战、去重、重启、一签一席、正文改版
  test_race.py     # 取消与最后签名的并发竞争
  test_settlement.py  # 分款取整、转让终止/生效、退票冲回、待扣回、并发、重启
  test_guarantee_fund.py # 担保基金、代偿批次、追偿顺序、退票反冲、缺口、限额与并发
  test_setoff.py   # 债务人绑定、最大平衡优化、占用、签署确认、到账覆盖优先级、撤销/失效/重启
run_demo.sh             # 自动起本机 uvicorn、跑签署 HTTP 演示、再独立验签
run_settlement_demo.sh  # 自动起本机 uvicorn、跑应收款结算 HTTP 演示
run_setoff_demo.sh      # 自动起本机 uvicorn、跑多方债务抵销 HTTP 演示
verify_certificate.py
requirements.txt
```

## 快速运行

依赖：Python 3.11+，并安装 `requirements.txt`（FastAPI、uvicorn、cryptography、httpx、pytest）。推荐使用虚拟环境：

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

若不建虚拟环境，也可把依赖装到当前用户环境（例如 `pip install --user -r requirements.txt`）；演示脚本会优先使用可用的 `.venv`，否则回退到 `python3`。

一键演示（原有签署流程）：

```bash
./run_demo.sh
```

一键演示（应收款结算）：

```bash
./run_settlement_demo.sh
```

一键演示（多方债务抵销）：

```bash
./run_setoff_demo.sh
```

`run_demo.sh` 会：

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

## 应收款结算（在签署服务之上扩展）

在保留上述全部签署流程的前提下，服务额外提供应收款结算能力。**只模拟单币种款项，所有金额都是整数分（cent），不接银行或任何真实支付渠道。** 全部写操作仍走 `BEGIN IMMEDIATE` 事务和持久化 `operation_id` 幂等，因此到账、退票、转让确认、划款并发时，结果等价于某个串行顺序，且失败不会只更新一边。

### 领域模型与不变量

- **应收款 `receivables`**：运营在一份**已完成（completed）**的协议下登记，含应收编号、债务人、原债权人、整数分本金；`remaining_cents` 是当前未收回本金。
- **持有份额 `receivable_holdings`**：每个债权人对该笔应收当前持有的**普通未收本金**。转让在份额之间移动，普通到账减少份额，退票按原收款人恢复份额。未绑定代偿时恒等式为 `remaining_cents = SUM(held_cents)`；发生代偿后为 `remaining_cents = SUM(普通 holdings) + SUM(代偿批次未收回余额)`。
- **转让申请 `transfer_applications`**：状态 `pending / effective / terminated`，绑定本笔应收、转出人、受让人、金额和一份自动生成的转让协议。
- **到账 `receipts` 与分款行 `receipt_allocations`**：一笔到账的不可变分款明细，记录每人毛份额、已冲回额、抵扣待扣回额和净入账额。
- **退票 `refunds` 与冲回行 `refund_reversals`**：可对一笔原到账分次退票，冲回行记录从可划余额扣了多少、记为待扣回多少。
- **结算账户 `settlement_accounts` + 流水账 `settlement_ledger`**：每个债权人一个跨应收款账户，含可划余额、待扣回、累计分款/冲回/已划。所有余额变动都追加一条 ledger，重启后可仅凭流水账重算并核对余额。

### 1. 登记应收款

```http
POST /receivables
```

```json
{
  "operation_id": "recv-1",
  "receivable_no": "AR-001",
  "agreement_id": "agr_...",
  "operator_account_id": "operator",
  "debtor": "债务人-甲",
  "original_creditor_id": "alice",
  "principal_cents": 10000
}
```

仅当 `agreement_id` 对应协议为 `completed` 时允许；应收编号全局唯一，重复编号返回 `RECEIVABLE_NO_CONFLICT`。登记后原债权人持有全部本金。

### 2. 申请本金转让并走现有签署流程

```http
POST /receivables/{receivable_id}/transfers
```

```json
{
  "operation_id": "trf-apply-1",
  "transferor_account_id": "alice",
  "transferee_account_id": "carol",
  "amount_cents": 400
}
```

服务生成一份两席位（转让人、受让人）、单阶段的转让协议，正文以 canonical JSON 绑定本笔应收、转出人、受让人、金额。两方**用既有挑战/签署接口**完成签署。申请**不冻结本金**，债务人在签署期间仍可付款。

运营确认：

```http
POST /transfers/{transfer_id}/confirmation
```

```json
{"operation_id": "trf-confirm-1", "operator_account_id": "operator"}
```

裁决规则：

- 只认该申请绑定的、**已完成**的转让协议；协议未签完返回 `TRANSFER_AGREEMENT_NOT_COMPLETED`，**不作终止判定**，申请保持 `pending`。
- 协议已完成后，按确认当时转出人**未收本金**判定：足额则在份额间移动本金，状态 `effective`；不足则**整笔转让终止**（`TRANSFER_INSUFFICIENT_PRINCIPAL`，HTTP 409 但终止决定已落库），即使后来退票恢复本金也**不会自动复活**，再次确认返回 `TRANSFER_TERMINATED`。
- 一次申请只能生效一次：重复生效确认返回 `TRANSFER_ALREADY_EFFECTIVE`。
- 已入账的分款不随转让移动，只移动当前未收本金。

### 3. 登记到账与最大余数法分款

```http
POST /receivables/{receivable_id}/receipts
```

```json
{
  "operation_id": "rcpt-1",
  "channel_serial_no": "CH-0001",
  "amount_cents": 300,
  "operator_account_id": "operator"
}
```

- 金额不得超过该笔应收剩余本金，否则 `RECEIPT_EXCEEDS_REMAINING`。
- 按**到账前**各债权人持有未收本金比例分款：先各自取整分（`floor(total*weight/sum)`），余下的分按小数余数从大到小各补一分，余数相同按账号升序。分款总和严格等于到账金额。
- 对应份额本金视为收回（减少 holdings），毛份额进入收款人结算账户；若该账户有待扣回欠额，先抵扣欠额，剩余才净入可划余额。
- 渠道流水号全局唯一：同流水号换内容提交返回 `CHANNEL_SERIAL_CONFLICT`；相同请求（含相同 `operation_id`）重试返回首次结果，不重复记账。

### 4. 分次退票与原行冲回

```http
POST /receipts/{receipt_id}/refunds
```

```json
{
  "operation_id": "rfnd-1",
  "channel_serial_no": "RF-0001",
  "amount_cents": 150,
  "operator_account_id": "operator"
}
```

- 可对一笔原到账分次登记，累计不得超过该笔到账金额，否则 `REFUND_EXCEEDS_RECEIPT`；退票流水号同样全局唯一。
- 按**原分款金额从大到小**（同额按账号升序）依次冲回各收款人尚未冲回的部分，并把对应本金**恢复给这些原收款人**，**不按退票当时的债权比例重算**（转让后的新债权人不会收到别人原分款的退票）。
- 冲回先扣原收款人可划余额；不足部分记为该账号**待扣回金额**。此后该账号的新分款先抵扣欠额；已经发生的划款记录不改写。

### 5. 划款

```http
POST /disbursements
```

```json
{
  "operation_id": "dsb-1",
  "account_id": "alice",
  "amount_cents": 100,
  "operator_account_id": "operator",
  "note": "实际划款"
}
```

划款不能超过账户当前可划余额，否则 `INSUFFICIENT_AVAILABLE_BALANCE`；划款成功生成不可变划款记录并减少可划余额。

### 6. 担保基金、代偿与追偿

担保基金是纯整数分模拟台账，不连接银行或真实支付渠道。一个基金可以为多笔应收垫款；一笔应收只能绑定一个基金。

#### 6.1 创建基金与登记注资

```http
POST /guarantee-funds
```

```json
{
  "operation_id": "fund-create-1",
  "fund_id": "fund_demo",
  "name": "小微担保基金",
  "operator_account_id": "operator"
}
```

`fund_id` 可省略，由服务端生成；`/funds` 是同义路径。随后登记注资：

```http
POST /guarantee-funds/fund_demo/contributions
```

```json
{
  "operation_id": "fund-contrib-1",
  "amount_cents": 100000,
  "operator_account_id": "operator",
  "note": "初始注资"
}
```

基金详情中的关键字段：

- `available_cents`：当前可用于新增代偿的资金；
- `gap_cents`：退票冲回基金但基金当前资金不足形成的缺口；
- `net_position_cents = available_cents - gap_cents`；
- 累计注资、代偿、追偿到账、退票冲回以及完整 `fund_ledger`。

后续注资和追偿到账都会**先补 `gap_cents`**，剩余才增加 `available_cents`；缺口未补足前新增代偿返回 `GUARANTEE_FUND_GAP_OUTSTANDING`。

#### 6.2 为应收绑定基金和固定限额

```http
POST /receivables/{receivable_id}/guarantee-binding
```

```json
{
  "operation_id": "bind-1",
  "fund_id": "fund_demo",
  "limit_cents": 30000,
  "operator_account_id": "operator"
}
```

`limit_cents` 也可写作 `compensation_limit_cents`。限额约束该应收**当前尚未收回的代偿批次本金合计**，不是累计代偿发生额；追偿到账恢复额度，退票恢复批次后会重新占用额度。一笔应收重复绑定返回 `RECEIVABLE_FUND_ALREADY_BOUND`。

#### 6.3 登记代偿，生成追偿批次

```http
POST /receivables/{receivable_id}/compensations
```

```json
{
  "operation_id": "comp-1",
  "creditor_account_id": "alice",
  "amount_cents": 3000,
  "operator_account_id": "operator"
}
```

金额必须同时满足：

1. 不超过该债权人当前**普通未收本金**（否则 `COMPENSATION_EXCEEDS_ORDINARY_PRINCIPAL`）；
2. 不超过该应收限额减未收回代偿本金后的额度（否则 `COMPENSATION_LIMIT_EXCEEDED`）；
3. 不超过基金 `available_cents`，且基金没有未补足缺口（否则 `GUARANTEE_FUND_INSUFFICIENT` / `GUARANTEE_FUND_GAP_OUTSTANDING`）。

代偿会在同一事务内：

- 减少该债权人的普通 holdings；
- 新增按代偿先后排序的追偿批次 `guarantee_compensations`；
- 从基金 `available_cents` 扣款；
- 把等额款项记入债权人结算账户，仍按“先抵扣 `pending_deduction_cents`，净额再增加 `available_cents`”处理。

代偿**不是债务人还款**：`receivables.remaining_cents` 不变。应收详情额外给出 `ordinary_remaining_cents`、`guarantee_outstanding_cents` 和 `compensation_batches`（每批含 `amount_cents`、`recovered_cents`、`outstanding_cents`）。

原有转让接口不变，但 holdings 在代偿时已经只代表普通未收本金，因此转让天然不能转走属于基金的追偿权；批次上的原受偿债权人仅保留审计含义。

#### 6.4 债务人到账：先追偿批次，再普通分款

仍使用原接口：

```http
POST /receivables/{receivable_id}/receipts
```

新规则仅适用于绑定后产生、且实际含基金批次分配的到账：

1. 按代偿批次 `seq` 从先到后偿还未收回批次；
2. 各批次金额进入其所属基金；若基金有缺口，先补缺口；
3. 到账金额的剩余部分才按原最大余数法分给当前普通债权人。

`GET /receipts/{receipt_id}` 同时返回：

- `allocations`：普通债权人分款；
- `guarantee_allocations` / `fund_allocations`：分到哪些基金代偿批次，以及补缺口/增加可用资金的金额。

#### 6.5 退票：先冲普通，再反序冲基金批次

仍使用：

```http
POST /receipts/{receipt_id}/refunds
```

对含基金分配的新到账，退票严格按以下顺序撤销**原到账的实际分配**：

1. 先冲普通分款；普通部分沿用原规则（原分款金额降序、同额账号升序），并恢复原收款人的普通本金、扣回其结算账户；
2. 普通部分不足后，再按**该笔到账偿还批次的反顺序**冲回基金分配；
3. 每冲回一笔基金分配，就恢复对应代偿批次的追偿本金，并从该基金当前资金扣款。

如果基金当前可用资金不足，不撤销已经发生的其他应收代偿，而是把不足额记为该基金的 `gap_cents`。若退票恢复批次导致某应收代偿余额超过绑定限额，已发生批次和退票全部保留；绑定视图会显示负的 `limit_headroom_cents` 和正的 `over_limit_cents`，此后任何新增正额代偿都被拒绝，直到新的追偿款把未收回代偿余额降到限额以内。

绑定前的旧到账没有 `receipt_guarantee_allocations` 记录，其退票继续走原有普通分款冲回逻辑；未绑定基金的应收完全保持原行为。

### 7. 多方债务抵销

多家企业互相欠款时，运营可在参与账号签署后让等额债权债务对销，只把未抵销本金留给原有到账/转让/代偿流程。**抵销确认不产生到账、结算账户入款/划款或基金流水。**

#### 7.1 一次性绑定文字债务人到登记账号

现有应收的 `debtor` 仍是自由文字。只有登记该应收的运营账号可把它一次性绑定到一个已登记账号；系统不按名称猜配：

```http
POST /receivables/{receivable_id}/debtor-binding
```

```json
{
  "operation_id": "debtor-bind-1",
  "operator_account_id": "operator",
  "debtor_account_id": "bob"
}
```

重复绑定返回 `RECEIVABLE_DEBTOR_ALREADY_BOUND`，运营账号不符返回 `NOT_RECEIVABLE_OPERATOR`。也支持 `PUT`、`/debtor-account-binding`、`/bind-debtor`、`POST /debtor-bindings` 等别名；登记应收时也可直接传 `debtor_account_id`。

#### 7.2 发起最大平衡抵销轮

```http
POST /setoff-rounds
```

```json
{
  "operation_id": "setoff-create-1",
  "operator_account_id": "operator",
  "items": [
    {
      "receivable_id": "recv_ab",
      "creditor_account_id": "alice",
      "limit_cents": 900
    },
    {
      "receivable_id": "recv_bc",
      "creditor_account_id": "bob",
      "limit_cents": 800
    },
    {
      "receivable_id": "recv_ca",
      "creditor_account_id": "carol",
      "limit_cents": 700
    }
  ]
}
```

服务逐项校验：

- 每项应收均由 `operator_account_id` 登记，且已绑定登记债务人账号；
- `creditor_account_id` 必须是该应收当前持有正额普通本金的债权人；
- 同一 `(receivable_id, creditor_account_id)` 不重复；
- 绑定债务人与当前债权人为同一账号的自我债权不进入正额方案；
- 每项容量为 `min(本轮上限, held_cents - 其他 pending 轮占用)`；
- 基金追偿批次不属于普通 holdings，因此不会被纳入。

把每个份额看成一条“绑定债务人账号 → 当前债权人账号”的有向边，抵销额是边流量；每个账号作为债务人的应付抵销合计必须等于作为债权人的应收放弃合计，即流量守恒。优化器求所有份额抵销额总和最大的整数分解；最大总额并列时，严格按 `items` 清单顺序先最大化第一项、再第二项，依此类推。纯函数 `signing_backend.setoff.optimize_setoff_flows` 有随机小图全枚举测试。

若最大总额为 0，接口返回 `409 NO_POSITIVE_SETOFF_PLAN`，不创建轮次或协议。成功时：

- 只占用优化选中的正额本金，而不是各项上限；
- 创建状态为 `pending` 的轮次和一份立即 `active` 的专用协议；
- 协议 canonical JSON 逐项写入 `round_id`、应收 ID/编号、债务人账号、债权人账号和抵销额；
- 每个有正额且守恒的参与账号恰好一个单阶段签署席位，完全复用现有挑战、Ed25519 签名、委托/取消和凭证流程。

兼容路径包括 `/setoffs`、`/debt-setoffs`、`/offset-rounds`、`/multilateral-setoff-rounds` 等；请求列表也可命名为 `shares`、`receivable_shares`、`setoff_items`。

#### 7.3 查看占用、轮次和协议

```http
GET /setoff-rounds
GET /setoff-rounds/{round_id}
GET /receivables/{receivable_id}/setoff-rounds
GET /receivables/{receivable_id}
```

轮次视图含 `status`（`pending / effective / revoked / invalid`，并提供 `state`、`round_status`、布尔状态别名）、`agreement`、`agreement_status`、`signed_count`、逐项 `items[].offset_cents`、每个账号的应付/应收合计与席位、`can_confirm` 和终止原因。

应收详情的每个 `holdings` 行额外给出：

```json
{
  "account_id": "alice",
  "held_cents": 1000,
  "occupied_cents": 600,
  "available_cents": 400
}
```

顶层也汇总 `occupied_ordinary_cents`、`available_ordinary_cents`，并提供 `holding_availability`、`setoff_round_ids` 等别名。登记应收的 201 响应仍保持精简 holdings 行。

#### 7.4 确认生效，且同一方案只能生效一次

所有席位签完后：

```http
POST /setoff-rounds/{round_id}/confirmation
{"operation_id":"setoff-confirm-1","operator_account_id":"operator"}
```

协议未完成时返回 `SETOFF_AGREEMENT_NOT_COMPLETED`，轮次保持 `pending`。确认事务重新检查轮次仍有效且本金可覆盖，然后：

1. 对每个 `(应收, 债权人)` 一次性减记 `offset_cents` holdings；
2. 按应收汇总并减少 `receivables.remaining_cents`；
3. 轮次置为 `effective`，记录确认 operation ID；
4. 不写 `receipts`、`receipt_allocations`、`settlement_accounts`、`settlement_ledger` 或基金流水。

相同 `operation_id` 重放首次结果；新 operation ID 对已生效轮次确认返回 `SETOFF_ROUND_ALREADY_EFFECTIVE`。

#### 7.5 占用期间的转让、代偿、到账与覆盖优先级

- 转让申请仍可按原规则发起和签署，但运营确认时若金额超过 `held_cents - pending setoff occupied`，返回 `TRANSFER_AMOUNT_OCCUPIED_BY_SETOFF`，转让保持 `pending`，占用释放后可用新 operation ID 再确认。
- 代偿金额不能超过未占用普通本金，否则返回 `COMPENSATION_PRINCIPAL_OCCUPIED_BY_SETOFF`；基金限额、可用资金等原校验不变。
- 真实到账仍按原优先级（绑定基金时先追偿批次）和各债权人**完整 held_cents** 最大余数法分款，不因为 setoff 占用而改变分款权重。
- 到账减记 holdings 后，在同一到账事务内按轮次 SQLite `rowid`（发起先后）重估所有 `pending` 轮：
  - 某轮每个份额都不超过“当前 holding − 更早保留轮已预留额”才保留；
  - 否则整轮置为 `invalid`，原因码 `SETOFF_COVERAGE_LOST`，明细含每个缺口；
  - 失效轮的所有 item 占用一起释放，不缩减已送签金额；
  - 若协议仍为 `active/draft`，同事务取消协议和未签席位；若已 `completed`，凭证保留但轮次不能确认。

之后原到账退票只按原分款行恢复本金，**不复活** `invalid` 轮，也不冲销已经 `effective` 的抵销。

#### 7.6 撤销与原协议入口取消

```http
POST /setoff-rounds/{round_id}/revocation
{"operation_id":"setoff-revoke-1","operator_account_id":"operator","reason":"..."}
```

未生效轮可由发起运营撤销；若专用协议尚未完成，会一并取消以阻止继续签署。也可以走原入口：

```http
POST /agreements/{agreement_id}/cancellation
{"operation_id":"cancel-1","initiator_account_id":"operator"}
```

取消事务在同一 `BEGIN IMMEDIATE` 中把关联轮置为 `revoked` 并释放全部占用。撤销/失效后确认分别返回 `SETOFF_ROUND_REVOKED` / `SETOFF_ROUND_INVALID`。

### 查询接口

| 方法与路径 | 内容 |
| --- | --- |
| `GET /receivables` / `GET /receivables/{id}` | 应收列表/详情，含普通未收本金、holdings 的占用/可用拆分、债务人绑定、担保绑定、各代偿/追偿批次余额、转让/到账/抵销轮 id |
| `POST /receivables/{id}/debtor-binding` / `GET /debtor-bindings/{id}` | 一次性把文字债务人绑定到已登记债务人账号 |
| `POST /setoff-rounds` / `GET /setoff-rounds` / `GET /setoff-rounds/{id}` | 发起/列表/查询多方抵销轮；列表支持 `?receivable_id=...&operator_account_id=...`，另有 `/setoffs`、`/offset-rounds` 等别名 |
| `POST /setoff-rounds/{id}/confirmation` / `.../revocation` | 签完后一次性减记生效，或撤销未生效轮并释放占用 |
| `POST /guarantee-funds` / `GET /guarantee-funds` / `GET /guarantee-funds/{id}` | 创建/列表/详情基金；详情含可用资金、缺口、累计金额、注资记录和基金流水（`/funds` 为别名） |
| `POST /guarantee-funds/{id}/contributions` | 登记注资；有缺口时先补缺口（另有 `/top-ups`、`/capital` 别名） |
| `POST /receivables/{id}/guarantee-binding` | 绑定唯一基金和固定代偿限额（`/fund-binding` 为别名） |
| `POST /receivables/{id}/compensations` / `GET /compensations` / `GET /compensations/{id}` | 登记代偿、查询批次；列表支持 `?receivable_id=...&fund_id=...` |
| `GET /transfers?receivable_id=...` / `GET /transfers/{id}` | 转让申请及绑定协议签署进度、生效/终止状态 |
| `GET /receipts/{id}` | 每笔到账的普通分款明细、基金/批次分配、每行已冲回/未冲回、关联退票 |
| `GET /refunds/{id}` | 每笔退票的普通冲回、基金批次反序冲回、余额扣减/待扣回/基金缺口拆分 |
| `GET /settlement-accounts` / `GET /settlement-accounts/{id}` | 可划余额、待扣回、累计分款/冲回/已划、**已划记录**与完整 ledger 流水 |

### 幂等、并发与重启

- 每个写接口都以 `(scope, operation_id)` 持久化请求指纹、状态码和响应体；同 ID 同内容重放首次结果，同 ID 换内容返回 `IDEMPOTENCY_REQUEST_CONFLICT`。到账/退票另有渠道流水号唯一约束兜底。
- 到账、退票、转让确认、划款、基金注资、绑定、代偿、债务人绑定、抵销轮发起/确认/撤销以及原协议取消钩子都在单条 `BEGIN IMMEDIATE` 事务内完成相关改动，SQLite 写锁把并发事务串行化，因此抵销轮与签署、到账、转让/代偿和本金改动共同等价于某个串行顺序，任何失败整体回滚，不会只更新一边。
- 转让“不足额终止”是一个**终局业务决定**：服务在同一事务内把申请置为 `terminated` 并以 409 返回（而不是抛错触发回滚），保证终止状态可靠落库且重放一致。
- 所有状态和 ledger 都在 SQLite 中，重启后状态、流水、幂等记录仍可核对；测试会重建 app 验证重放与流水账重算。

### 结算演示与测试

只运行担保基金专项测试：

```bash
python3 -m pytest tests/test_guarantee_fund.py -q
```

只运行多方抵销专项测试：

```bash
python3 -m pytest tests/test_setoff.py -q
```

运行全部测试：

```bash
python3 -m pytest -q
```

```bash
./run_settlement_demo.sh
./run_setoff_demo.sh
```

结算脚本会起本机 uvicorn，走真实 HTTP 演示：登记应收、申请并签署转让协议、运营确认、两笔到账（含重试与流水号冲突拒绝）、划款、分次退票（含可划余额不足转待扣回）、新分款抵扣欠额，并落盘查询快照。

抵销脚本会演示三笔首尾相接应收的绑定、最大平衡优化、占用/可用查询、三个账号通过现有挑战流程签署、运营确认后一次性减记，并校验没有结算账户余额或流水产生。

## 自动化测试说明

```bash
python3 -m pytest -q
```

覆盖（共 46 个测试，含多方抵销、担保基金专项、并发多轮与重启）：

- 两阶段门和完整凭证验证；
- 委托、连续委托、环拒绝、越权委托拒绝；
- 撤销后再委托回同一账号，旧挑战仍 `AUTHORITY_STALE`；
- 已完成席位不能再委托/撤销；
- 同一账号受托两个席位时，一个签名不能用于另一个席位；
- 同一挑战不能产生第二事实；
- operation ID 同内容重放、换内容冲突；
- 取消后正文改版必须创建新协议，旧签名不能验证新正文；
- 重启后状态、幂等和挑战消费状态仍有效；
- 单轮和多轮重复的“取消 vs 最后签名”竞争一致性；
- 应收只能登记在已完成协议下、应收编号唯一；
- 最大余数法分款（取整 + 余数补分 + 同余数账号升序），纯函数对 1..1000 全量校验总和守恒；
- 转让：未签完不终止、不足额整笔终止且退票后不复活、生效只移动未收本金且仅一次；
- 退票：分次累计上限、按原分款行（金额降序、同额账号升序）冲回并把本金恢复给原收款人；
- 待扣回：可划余额不足转欠额、新分款先抵扣、已划记录不改写、划款不得超可划余额；
- 渠道流水号换内容拒绝、相同请求重试不重复记账；
- 重启后转让终止状态、余额与流水账仍可核对（ledger 重算余额、本金/分款/冲回守恒）；
- 担保基金：创建/注资、唯一绑定、三重代偿限额、结算账户先抵待扣回、代偿不减少应收总未收额；
- 追偿到账按批次先后分配给基金，剩余金额才按原规则分给普通债权人；
- 退票先冲普通分款、再按该到账批次反序冲基金并恢复批次本金；基金不足记缺口，后续注资/追偿先补缺口；
- 退票导致超限额时保留历史并阻止新增代偿，追偿恢复额度后可继续；转让只能移动普通未收本金；
- 绑定前旧到账和未绑定应收保持原分款/退票规则；旧 `settlement_ledger` CHECK 表会在启动时幂等迁移；
- 担保基金重启重放不重复注资/代偿，20 并发代偿不会突破基金可用资金；
- 债务人账号一次性绑定、越权/重复绑定拒绝，应收详情区分普通本金的占用与可用部分；
- 多方抵销：循环图最大平衡额、清单顺序 lex tie-break（3000 组随机小图对拍全枚举）、自我债权排除、重复组合拒绝、无正额方案不建协议；
- 抵销发起即占用选中本金并生成专用协议和每账号一席位；确认才一次性减记 holdings/remaining，且无到账、账户或基金流水；
- 占用阻止转让确认/代偿动用被占部分；到账仍按完整 holdings 分款并按发起先后淘汰无法足额覆盖的整轮，释放其他应收占用；
- 撤销或原协议取消释放占用；失效/撤销后不能继续签，已完成凭证保留但不能确认；退票不复活失效轮、不反冲已生效抵销；
- 抵销轮重启后 operation ID 重放不重复发起、释放或扣减；到账/退票/转让确认/划款并发等价于某串行顺序，无半写；同操作 ID 高并发只入账一次。

## 生产化前仍需补充的事项

本任务明确要求用本机密钥模拟签署人、不接外部身份系统，因此当前 HTTP 请求中的 `actor_account_id` / `initiator_account_id` 是模拟身份字段，没有加真实登录鉴权。生产化前应增加：

- 用户认证和服务端会话/令牌授权，而不是信任请求体中的账号 ID；
- 更严格的账号公钥注册证明（例如注册时用对应私钥签名注册挑战）；
- HTTPS、限流、审计日志访问控制；
- 挑战过期时间和 nonce 清理策略；
- SQLite 备份或迁移到 PostgreSQL；
- 多 worker 部署时继续依赖数据库事务/唯一约束，而不是进程内锁。
