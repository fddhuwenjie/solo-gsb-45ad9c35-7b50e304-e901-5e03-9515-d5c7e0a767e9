# 委托能力链验证 API（Delegation Capability Chain）

客户端提交一条**根授权**和若干以 `parent_id` 相连的**委托令牌（capability token）**。
服务端完成：

1. **HMAC-SHA256 验签** —— 对规范化 JSON 报文验签（每主体独立密钥）；
2. **签发者检查** —— 根授权必须由配置的根主体签发；委托令牌的 `issuer` 必须等于父令牌的 `subject`；
3. **结构检查** —— 断链、重复 id、多根、分叉、环、与根不可达；
4. **逐级收窄** —— 子令牌的路径模式、HTTP 方法集合、时间窗、`allow_ip` CIDR 只能比父令牌更窄；
5. **请求级判定** —— 给定请求路径、方法、时间、来源 IP 与请求主体，返回 `allow` / `deny`、首个失败节点和完整验证轨迹；
6. **按时间生效的撤销审计** —— 运维方可对链上任一令牌追加**不可变撤销事件**（含生效时间、原因、幂等键），
   求值按请求时间解释事件：生效后该节点及其后代一律拒绝，生效前的历史请求仍按原链判定；
7. **一次性访问核销** —— 对已提交链的**末端令牌**执行一次性核销：以服务端接收时刻重算全部判定，
   仅在末端且允许时记录核销；同一令牌只能成功核销一次（并发仅一笔成功），
   `request_key` 成功重放返回首次结果（即使令牌随后过期 / 被撤销），换内容冲突；
   判定拒绝与目标不符均不核销、不占用 `request_key`。

相同 `chain_id` 的重放**幂等**（返回 200 + `replayed=true`）；相同 `chain_id` 内容变化返回 **409 Conflict**。
撤销与核销同样按 `request_key` 幂等：同键同内容重放原结果，同键换目标/内容返回 **409 Conflict**。

技术栈：Python · FastAPI · Pydantic v2 · SQLite（标准库 `sqlite3`）· Uvicorn。

---

## 一条命令启动

```bash
docker compose up --build
```

- API：<http://localhost:8000>
- 交互式文档（Swagger UI）：<http://localhost:8000/docs>
- 健康检查：<http://localhost:8000/health>
- SQLite 数据持久化在命名卷 `chain-data`（容器内 `/data/capabilities.db`）。

停止：`Ctrl+C`；清空数据重来：`docker compose down -v`。

本地裸跑（无需 Docker）：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## 快速演示

容器启动后会自动播种演示主体（可通过 `SEED_DEMO_PRINCIPALS=false` 关闭）：

| 主体        | HMAC 密钥（仅演示，生产请覆盖）         |
| ----------- | --------------------------------------- |
| `root`      | 环境变量 `ROOT_HMAC_SECRET`（见 compose）|
| `service-a` | `demo-secret-service-a`                 |
| `service-b` | `demo-secret-service-b`                 |
| `alice`     | `demo-secret-alice`                     |

用随仓库附带的脚本生成一条已签名的合法链（`root → service-a → service-b`）、
提交、幂等重放、求值，对链末端执行一次性核销（含重放与重复核销冲突），
再追加一条撤销并演示“生效后拒绝 / 生效前仍按原链判定”（需要本地 Python 3.10+）：

```bash
# 只打印已签名的提交报文
PYTHONPATH=. python scripts/demo_chain.py print

# 提交 + 重放 + 求值（默认 http://127.0.0.1:8000，可用 BASE_URL 覆盖）
PYTHONPATH=. python scripts/demo_chain.py submit
```

---

## 数据模型

### 令牌 `CapabilityToken`

| 字段          | 类型                | 说明                                                                 |
| ------------- | ------------------- | -------------------------------------------------------------------- |
| `token_id`    | string              | 令牌唯一标识                                                         |
| `parent_id`   | string \| null      | 父令牌 id；根授权为 `null`                                           |
| `chain_id`    | string              | 所属能力链 id（提交体内所有令牌必须一致）                            |
| `issuer`      | string              | 签发主体；需事先注册其 HMAC 密钥                                     |
| `subject`     | string              | 被授权主体                                                           |
| `path_pattern`| string              | 资源路径 glob，以 `/` 开头；`*` 匹配单段，`**` 只能作末段（含 0 段）  |
| `methods`     | string[]            | 允许的 HTTP 方法（自动去重并转大写，至少 1 个）                      |
| `not_before`  | date-time           | 生效时间，**必须携带时区**（如 `...Z`）                              |
| `not_after`   | date-time           | 失效时间（严格晚于 `not_before`）                                    |
| `allow_ip`    | string \| null      | 可选 CIDR，如 `10.0.0.0/8`；必须是规范网络地址                       |
| `signature`   | string              | 64 位十六进制 HMAC-SHA256                                            |

### 提交体 `ChainSubmission`

```json
{ "chain_id": "demo-chain-0001", "tokens": [ { ...根令牌... }, { ...委托令牌... } ] }
```

### 求值请求 `EvaluateRequest`

| 字段           | 必填 | 说明                                         |
| -------------- | ---- | -------------------------------------------- |
| `request_path` | 是   | 实际请求路径                                 |
| `method`       | 是   | 实际 HTTP 方法（大小写不敏感）               |
| `at`           | 是   | 请求时间，必须携带时区                       |
| `source_ip`    | 否   | 链上任一令牌含 `allow_ip` 时需要提供         |
| `body`         | 否   | 任意 JSON；服务不据其授权，只记录 SHA-256 指纹到轨迹 |

### 撤销请求 `RevocationRequest`

`POST /api/v1/chains/{chain_id}/revocations`（`chain_id` 取自 URL 路径）：

| 字段           | 必填 | 说明                                              |
| -------------- | ---- | ------------------------------------------------- |
| `token_id`     | 是   | 被撤销的令牌；必须已存在于该链                    |
| `effective_at` | 是   | 撤销生效时间，必须携带时区；可指向未来（到期才解释） |
| `reason`       | 是   | 撤销原因（审计说明，非空）                        |
| `request_key`  | 是   | 客户端幂等键；同键内容必须一致，且**全局唯一**    |

### 核销请求 `RedeemRequest`

`POST /api/v1/chains/{chain_id}/redeem`（`chain_id` 取自 URL 路径）：

| 字段           | 必填 | 说明                                              |
| -------------- | ---- | ------------------------------------------------- |
| `token_id`     | 是   | 被核销令牌；**必须为链末端**（唯一根→唯一子链的最后一个令牌） |
| `request_key`  | 是   | 客户端幂等键；同键内容必须一致，且**全局唯一**（仅成功核销占用） |
| `request_path` | 是   | 实际请求路径                                      |
| `method`       | 是   | 实际 HTTP 方法（大小写不敏感）                    |
| `source_ip`    | 否   | 链上任一令牌含 `allow_ip` 时需要提供              |
| `body`         | 否   | 任意 JSON；服务只记录 SHA-256 指纹到轨迹，正文随核销记录留档 |

> 核销请求**不提供时间**：判定时间固定为服务端接收该请求的时刻（UTC）。

---

## HTTP 接口

### `POST /api/v1/principals`

注册签发主体及其 HMAC 密钥（演示 / 引导用；生产建议关闭播种后自行注册）。

```json
{ "name": "service-a", "hmac_secret": "s3cr3t" }
```

- `201` 注册成功；`409` 主体已存在。

### `POST /api/v1/chains`

提交一条能力链。

- `201 Created`：新 `chain_id`，已持久化（**完整性失败也会持久化**，含失败轨迹，便于审计）；
- `200 OK`：相同 `chain_id` 且内容逐字节等价（规范化后 SHA-256 相同），`replayed=true`；
- `409 Conflict`：相同 `chain_id` 但内容不同，响应体给出双方哈希：

```json
{
  "detail": {
    "detail": "chain_id='x' 已存在但内容不同；相同 chain_id 不允许提交不同内容",
    "chain_id": "x",
    "existing_sha256": "…",
    "received_sha256": "…"
  }
}
```

响应中的 `integrity` 字段：

```json
{
  "allow": true,
  "first_failed_node": null,
  "first_failed_reason": null,
  "ordered_token_ids": ["token-root", "token-a", "token-b"],
  "trace": [
    {
      "token_id": "token-a",
      "issuer": "service-a",
      "subject": "service-b",
      "parent_id": "token-root",
      "is_root": false,
      "checks": [
        { "name": "signature", "passed": true, "detail": "HMAC-SHA256 验签通过", "reason": null },
        { "name": "issuer_chain", "passed": true, "detail": "…", "reason": null },
        { "name": "path_narrows", "passed": true, "detail": "…", "reason": null },
        { "name": "methods_narrow", "passed": true, "detail": "…", "reason": null },
        { "name": "time_window_narrows", "passed": true, "detail": "…", "reason": null },
        { "name": "ip_range_narrows", "passed": true, "detail": "…", "reason": null }
      ]
    }
  ]
}
```

### `GET /api/v1/chains/{chain_id}`

返回存储的链：令牌列表、内容哈希、创建时间、提交时的完整性报告，以及按追加顺序排列的
**撤销事件列表** `revocations` 与**成功核销记录列表** `redemptions`（从未发生时均为 `[]`）；
不存在返回 `404`。

```json
{
  "chain_id": "demo-chain-0001",
  "content_sha256": "…",
  "created_at": "2026-10-01T00:00:00+00:00",
  "integrity": { /* 与提交时一致的完整性报告 */ },
  "tokens": [ /* …令牌… */ ],
  "revocations": [
    {
      "chain_id": "demo-chain-0001",
      "token_id": "token-a",
      "effective_at": "2026-10-01T12:00:00+00:00",
      "reason": "运维安全事件：疑似密钥泄露",
      "request_key": "ops-revoke-2026-0001",
      "content_sha256": "…",
      "created_at": "2026-10-01T09:30:00+00:00"
    }
  ],
  "redemptions": [
    {
      "chain_id": "demo-chain-0001",
      "token_id": "token-b",
      "request_key": "access-redeem-2026-0001",
      "request_path": "/files/reports/2026/q1.pdf",
      "method": "GET",
      "source_ip": "10.1.2.3",
      "request_body": { "q": "demo" },
      "content_sha256": "…",
      "evaluated_at": "2026-10-01T09:00:00+00:00",
      "redeemed_at": "2026-10-01T09:00:00+00:00",
      "created_at": "2026-10-01T09:00:00+00:00"
    }
  ]
}
```

### `POST /api/v1/chains/{chain_id}/revocations`

在**同一 SQLite 事务**内确认 `token_id` 存在于该链，并追加一条不可变撤销事件。

```bash
curl -sS -X POST http://localhost:8000/api/v1/chains/demo-chain-0001/revocations \
  -H 'Content-Type: application/json' \
  -d '{
    "token_id": "token-a",
    "effective_at": "2026-10-01T12:00:00Z",
    "reason": "运维安全事件：疑似密钥泄露",
    "request_key": "ops-revoke-2026-0001"
  }'
```

- `201 Created`：新事件已落库；
- `200 OK`：相同 `request_key` 且内容逐字节等价（规范化 SHA-256 相同），`replayed=true`，返回**原事件与原结果**；
- `409 Conflict`：
  - 相同 `request_key` 但更换了目标令牌 / 生效时间 / 原因（即使指向另一条链）；
  - 目标令牌此前已被撤销（`已撤销令牌不得重复生效`，即便换 `request_key`）；
- `404 Not Found`：链不存在，或令牌不属于该链；
- `422`：`effective_at` 未携带时区等输入校验失败。

`201` / `200` 响应体：

```json
{
  "replayed": false,
  "event": {
    "chain_id": "demo-chain-0001",
    "token_id": "token-a",
    "effective_at": "2026-10-01T12:00:00+00:00",
    "reason": "运维安全事件：疑似密钥泄露",
    "request_key": "ops-revoke-2026-0001",
    "content_sha256": "…",
    "created_at": "2026-10-01T09:30:00+00:00"
  },
  "affected_token_ids": ["token-a", "token-b"]
}
```

`affected_token_ids` 为被撤销节点**自身及其全部后代**，按原链根→叶顺序列出
（上例中 `token-b` 是 `token-a` 的下游委托，故一并失效）。

撤销事件**只追加、不可变**：服务不提供修改或删除接口；数据库层以
`request_key UNIQUE` 与 `(chain_id, token_id) UNIQUE` 双重约束兜底并发。

### `POST /api/v1/chains/{chain_id}/evaluate`

对已存链执行请求级判定（完整性检查每次实时重算）。返回：

```json
{
  "chain_id": "demo-chain-0001",
  "decision": "allow",
  "first_failed_node": null,
  "first_failed_reason": null,
  "body_sha256": "…",
  "first_revoked_node": null,
  "trace": [ /* 每个节点：完整性检查 + 请求级检查 */ ]
}
```

请求级检查项（按链上每个节点追加）：

| 检查名             | 失败原因                | 含义                          |
| ---------------- | -------------------------- | ----------------------------- |
| `revocation_active`| `revoked`                  | 请求时间点该节点自身（或其祖先）已被生效撤销 |
| `time_valid`     | `before_not_before` / `after_not_after` | 请求时间超出令牌有效期（边界含端点） |
| `method_allowed` | `method_not_allowed`       | 方法不在令牌方法集合          |
| `path_covered`   | `path_not_covered`         | 路径不匹配令牌 glob           |
| `ip_allowed`     | `ip_not_allowed`           | 来源 IP 不在 `allow_ip` 网段 |

#### 撤销如何参与求值

撤销按**请求时间 `at`** 解释，而非按事件提交时间：

- 仅当 `at >= effective_at` 时事件生效；生效事件使**目标节点及其全部后代**拒绝
  （后代节点的轨迹写明“祖先令牌 X 已被撤销，本节点作为其后代同步失效”）；
- 当 `at < effective_at` 时事件**完全不解释**：历史请求仍按原链判定，可正常 `allow`；
  因此允许提前登记一条未来生效的撤销；
- 响应顶层 `first_revoked_node` 标出按链顺序**最先受撤销影响的节点**（即最靠近根的
  被撤销节点本身，而非其后代）；它同时通常也是 `first_failed_node`（reason 为 `revoked`）。

求值必须**整条链所有节点**全部通过才为 `allow`；`first_failed_node` /
`first_failed_reason` 指向按链顺序（根→叶，先完整性后请求级）遇到的第一个失败。

---

## 一次性访问核销 `POST /api/v1/chains/{chain_id}/redeem`

对已提交链的**末端令牌**做一次性（exactly-once）访问核销。整个流程在
**同一 SQLite 事务**（`BEGIN IMMEDIATE`，写锁串行化）内完成：

1. 以**服务端接收时刻**（UTC，响应中的 `evaluated_at`）重算现有验签、逐级收窄、
   按时间解释的撤销状态，以及路径 / 方法 / 时间窗 / 来源 IP 的请求级判定（复用只读求值的同一引擎）；
2. 仅当目标确为**链末端**且判定为 `allow` 时才追加一条不可变核销记录（`redeemed_at`）；
3. 同一令牌**只能成功核销一次**：并发请求仅一笔 `201`，其余均得到明确的
   `409`（含赢家的 `existing_request_key` 与 `redeemed_at`）；
4. 成功核销后，同一 `request_key` 带**相同内容**重试，返回**首次结果**
   （`200`、`replayed=true`、首次的轨迹与 `redeemed_at`），即使令牌随后过期或被撤销；
   同键换内容（换目标令牌 / 路径 / 方法 / IP / 请求体）返回 `409`；
5. 目标不是链末端，或判定为 `deny` 时，**既不核销，也不占用 `request_key`**——
   后续有效请求仍可尝试，同一 `request_key` 也还能用于一次成功核销。

```bash
curl -sS -X POST http://localhost:8000/api/v1/chains/demo-chain-0001/redeem \
  -H 'Content-Type: application/json' \
  -d '{
    "token_id": "token-b",
    "request_key": "access-redeem-2026-0001",
    "request_path": "/files/reports/2026/q1.pdf",
    "method": "GET",
    "source_ip": "10.1.2.3",
    "body": {"q": "demo"}
  }'
```

成功核销（`201 Created`）响应：

```json
{
  "chain_id": "demo-chain-0001",
  "token_id": "token-b",
  "request_key": "access-redeem-2026-0001",
  "redeemed": true,
  "replayed": false,
  "evaluated_at": "2026-10-04T09:00:00.000000Z",
  "redeemed_at": "2026-10-04T09:00:00.000000Z",
  "decision": "allow",
  "first_failed_node": null,
  "first_failed_reason": null,
  "body_sha256": "…",
  "first_revoked_node": null,
  "trace": [ /* 与 /evaluate 同构的完整判定轨迹：完整性 + 请求级 */ ]
}
```

状态码与重放语义：

| 情况 | 状态码 | 响应要点 |
| ---- | ------ | -------- |
| 首次且末端 + 允许 | `201` | `redeemed=true`、`replayed=false`，记录核销 |
| 同 `request_key` 同内容重试 | `200` | `replayed=true`，回放首次结果（令牌事后过期 / 撤销也不变） |
| 末端但本次判定拒绝 | `200` | `redeemed=false`、`decision="deny"`、完整轨迹；不核销、不占键 |
| 同 `request_key` 换内容 | `409` | 给出双方 `existing_sha256` / `received_sha256` |
| 目标非链末端 | `409` | 附 `chain_tip_token_id`（结构异常无法确定时为 `null`） |
| 令牌此前已核销（含并发输家） | `409` | 附 `existing_request_key` 与赢家 `redeemed_at` |
| 链 / 令牌不存在 | `404` | 令牌不属于该链按不存在处理 |
| 输入非法（方法 / IP） | `422` | Pydantic 校验错误 |

> 核销是**只追加**的成功记录：数据库以 `request_key UNIQUE` 与
> `(chain_id, token_id) UNIQUE` 双重约束兜底并发；被拒绝 / 目标不符的尝试不落任何记录。
> 核销不影响原有只读 `/evaluate`：后者仍每次实时重算，令牌被核销后照常可按时间判定为 allow/deny。

---

## 规范化 JSON 与签名（重要）

签名覆盖除 `signature` 外的下列字段（固定集合、固定键顺序无关，因为规范化时按键排序）：

```
token_id, parent_id, chain_id, issuer, subject,
path_pattern, methods, not_before, not_after, allow_ip
```

规则：

1. **规范化 JSON**（RFC 8785 风格）：无多余空白；键按 UTF-16 码元升序；
   不转义非 ASCII；`methods` 排序后参与签名（集合顺序无关）；
2. 时间统一渲染为 UTC：`YYYY-MM-DDTHH:MM:SS[.ffffff]Z`。
   **因此提交时的时间字符串应使用 UTC 的 `Z` 形式**（如 `2026-01-01T00:00:00Z`），
   否则带偏移量（`+08:00`）的原始文本与服务规范化结果不一致会导致验签失败；
3. 用签发者的 HMAC 密钥对规范化字节串做 `HMAC-SHA256`，输出 64 位小写 hex 填入 `signature`。

Python 侧可直接复用 `app.security`：

```python
from app.security import compute_signature
token = { ...除 signature 外的字段... }
token["signature"] = compute_signature(token, issuer_secret)
```

使用其他语言/`curl` 时，请严格按上述规则自行构造规范化报文。

### 路径 glob 语义

- 以 `/` 开头，`*` 匹配单个非空路径段，`**` 只能作为**末段**且匹配任意数量段（含 0 段）：
  - `/files/**` 匹配 `/files`、`/files/a`、`/files/a/b/c`；
  - `/files/*` 只匹配 `/files/<单段>`；
  - 其余段为字面量精确匹配。
- 收窄判定按段比较：父 `*` 接受子为 `*` 或字面量；父字面量只接受相同字面量；
  子在父的 `**` 前结束（如 `/files` 收窄自 `/files/**`）合法。

### 收窄规则汇总

| 维度     | 规则                                                                 |
| -------- | -------------------------------------------------------------------- |
| 路径     | 子模式允许的所有具体路径必须被父模式覆盖                             |
| 方法     | `子方法集合 ⊆ 父方法集合`                                            |
| 时间窗   | `[子.nb, 子.na) ⊆ [父.nb, 父.na)`                                    |
| IP 网段  | 父无限制→子可加限制；父有限制而子取消→拒绝；都有→子网段必须是父子网段 |

---

## 完整性失败原因码

| reason                    | 触发条件                                   |
| ------------------------- | ------------------------------------------ |
| `missing_root`            | 没有 `parent_id=null` 的令牌               |
| `multiple_roots`          | 存在多个根授权                             |
| `duplicate_id`            | 同一 `token_id` 重复出现                   |
| `broken_link`             | `parent_id` 指向不存在的令牌               |
| `cycle`                   | 沿 `parent_id` 上行检测到环                |
| `branch`                  | 同一父令牌被两个子令牌引用（链不允许分叉） |
| `disconnected`            | 令牌无法从根授权到达                       |
| `unknown_issuer`          | 签发主体未注册，无法取密钥                 |
| `bad_signature`           | HMAC 验签不通过                            |
| `issuer_mismatch`         | 根签发者不是配置根主体，或委托者 ≠ 父主体  |
| `path_widens`             | 子路径相对父路径构成放大                   |
| `method_widens`           | 方法集合放大                               |
| `time_window_widens`      | 时间窗放大                                 |
| `ip_widens`               | IP 网段放大                                |
| `revoked`                 | 求值时该节点自身（或其祖先）已被生效撤销   |

---

## 环境变量

| 变量                     | 默认值                         | 说明                                   |
| ------------------------ | ------------------------------ | -------------------------------------- |
| `DATABASE_PATH`          | `/data/capabilities.db`        | SQLite 文件路径（目录自动创建）        |
| `ROOT_PRINCIPAL`         | `root`                         | 根授权唯一合法签发者                   |
| `ROOT_HMAC_SECRET`       | `dev-root-secret-change-me`    | 根主体 HMAC 密钥，**生产必须覆盖**     |
| `SEED_DEMO_PRINCIPALS`   | `true`                         | 是否在启动时播种演示主体               |

---

## 项目结构

```
.
├── app/
│   ├── main.py        # FastAPI 路由：提交/重放/冲突/查询/求值/撤销/一次性核销
│   ├── models.py      # Pydantic 模型与输入校验
│   ├── security.py    # 规范化 JSON、HMAC、glob、收窄原语、内容指纹
│   ├── engine.py      # 结构/签名/签发者/收窄/请求级验证引擎、链末端识别与轨迹
│   ├── database.py    # SQLite 初始化、主体/链/撤销/核销持久化
│   └── config.py      # 环境变量配置
├── scripts/demo_chain.py
├── tests/             # pytest：82 个用例（端到端 API、原语单测、撤销审计、一次性核销）
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 运行测试

```bash
pip install -r requirements-dev.txt
pytest -q
```
