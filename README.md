# 商用密码辅助测评工具：最小纵切面

面向 Nginx 配置与 X.509 证书的**密评辅助测评最小闭环**：

```text
材料导入 → 解析 → 证据整理 → 版本化规则判定 → 风险识别
        → JSON 报告初稿 → 证据包导出 → 独立核验（完整性 + 规则重放）
```

本轮只承诺配置与证书两类输入，以及规则包里已经实现的检查。目录里有 49 项标准指标，
但只有 4 项有自动规则 —— **不要把指标目录说成 49 项自动判定**，也不要把报告说成
完整的 GB/T 39786 合规结论。每条 `COMPLIANT` 只表示「对应的那条已实现规则给出了
符合建议」。

契约版本 `0.2.1-mvp`　规则包版本 `0.3.0-mvp`

## 环境

Python 3.12 + Pydantic v2（`requirements-contracts.txt`）；真实解析证书还需要
`cryptography`（`requirements.txt`）。仓库自带 `.venv` 可直接使用。

```powershell
cd <仓库根>
.\.venv\Scripts\python.exe -m pip install -r requirements.txt   # 需要时
```

> 必须在仓库根目录运行：`python -m mvp_flow` 与 `python -m unittest` 都依赖
> 「当前目录在 `sys.path` 里」。

## 跑测试

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests        # 163 项
```

## 跑一次测评（统一入口）

```powershell
# 仓库预置的三组样例
.\.venv\Scripts\python.exe -m mvp_flow --all --mode real --now 2026-09-28T08:00:00Z

# 单个样例
.\.venv\Scripts\python.exe -m mvp_flow complete --mode real --now 2026-09-28T08:00:00Z

# 外部案例目录（非预置输入）
.\.venv\Scripts\python.exe -m mvp_flow my-case --mode real --case-dir D:\cases\my-case `
    --out D:\out --now 2026-10-01T02:00:00Z
```

| 参数 | 说明 |
|---|---|
| `case` | 案例名。用预置样例时必须是 `complete` / `missing_binding` / `risky`；配合 `--case-dir` 时可自取名字 |
| `--all` | 按固定顺序跑完仓库预置样例（不能与 `--case-dir` 同用） |
| `--mode` | `fixture` 读契约样例快照（**替身**）；`real` 解析真实材料 |
| `--case-dir` | 外部案例目录（**只读**），需配合 `--mode real` |
| `--out` | 输出根目录，默认仓库下的 `results/` |
| `--run-id` | 运行标识，默认取本次执行时钟 |
| `--now` | 固定生成/核查时刻（ISO8601，带 `Z`）；不传则用当前 UTC 时间 |

退出码：全部阶段 `SUCCEEDED` 为 `0`，否则 `1`。

### 输出布局

```text
<输出根>/<案例名>/runs/<run_id>/
    run-record.json      本次运行的完整记录（每阶段的真实/替身边界、成败、失败原因）
    report/              assessment-draft.json 报告初稿
    bundle/              证据包：manifest.json + snapshot/ + decisions/ + materials/ + 报告副本
    materials/           受控导入的材料原件副本
```

**不会覆盖历史运行**：`run_id` 缺省取本次执行时钟，所以每次运行落在自己的目录里。
同一 `run_id` 重复运行是幂等复现（相同输入 + 相同 `--now` → 相同产物），而不是各堆一份。

## 准备一个外部案例

案例目录里放：

```text
<案例目录>/
    case.json              必需
    nginx.conf             必需
    证书文件 .pem / .der    必需
    review_events.json     可选；要绑定成立就得有
```

`case.json`：

```json
{
  "project_id": "PRJ-C01",
  "environment": "PROD",
  "asset_id": "WEB-01",
  "link_id": "LINK-01",
  "evaluation_time": "2026-10-01T02:00:00Z",
  "rule_version": "0.3.0-mvp",
  "previous_snapshot_id": "NONE"
}
```

`review_events.json`（人工确认绑定；没有它绑定就无法成立）：

```json
[
  {
    "action": "CONFIRM_BINDING",
    "target_predicate": "service_uses_certificate",
    "confirmed_asset_id": "WEB-01",
    "actor_id": "reviewer-01",
    "reason": "现场确认 WEB-01 的 nginx 使用该证书"
  }
]
```

四个硬约束：

1. `rule_version` 必须写 `0.3.0-mvp`。写别的值判定引擎会**显式拒绝**，这是有意设计。
2. `nginx.conf` 里 `ssl_certificate` 的**文件名**要和证书文件名对得上 —— 代码靠
   basename 关联「配置里的证书路径」与「证书材料」。对不上，绑定就不成立。
3. `confirmed_asset_id` 要和 `case.json` 的 `asset_id` 一致。
4. `evaluation_time` 必须带 UTC 时区（`...Z`）。

## 验收：三种场景的预期结果

```powershell
# 1) 正常绑定 → 唯一符合
.\.venv\Scripts\python.exe -m mvp_flow complete --mode real --now 2026-09-28T08:00:00Z
#    预期：流程 SUCCEEDED，结论 EVALUATED，三条判定 proposed_label 均为 COMPLIANT，风险 0 条

# 2) 缺绑定 → 停在待补证
.\.venv\Scripts\python.exe -m mvp_flow missing_binding --mode real --now 2026-09-28T08:00:00Z
#    预期：结论 PENDING_EVIDENCE，proposed_label 为 null，缺口 MISSING_BINDING

# 3) 风险材料 → 判定与风险两套口径
.\.venv\Scripts\python.exe -m mvp_flow risky --mode real --now 2026-09-28T08:00:00Z
#    预期：结论 PENDING_EVIDENCE；密钥强度判 NON_COMPLIANT；
#          证书缺用途扩展 → 待补证 + MISSING_CERTIFICATE_EVIDENCE 缺口；风险 7 条
```

三组都应为「完整性 PASS / 重放 PASS」。

### 失败路径（应当失败，并说明原因）

| 动作 | 预期 |
|---|---|
| 改动证据包内任一文件 | 完整性 FAIL，`E_BUNDLE_DIGEST_MISMATCH`；并因包不完整拒绝重放 |
| 删除包内列出的文件 | 完整性 FAIL，`E_BUNDLE_FILE_MISSING` |
| 规则包内容与清单记录的 `rule_sm3` 不一致 | 重放 FAIL，`E_REPLAY_RULE_MISMATCH` |
| 清单记录的 `rule_version` 不被当前规则包接受 | 重放 FAIL，`E_REPLAY_RULE_MISMATCH` |
| 同步改写判定与清单摘要（骗过完整性） | 重放 FAIL，`E_REPLAY_MISMATCH` |

## 证据包的可信边界（重要）

- `integrity_status=PASS` **只**表示包内文件与其清单记录的 SM3 一致。
- 清单本身**没有签名、没有身份认证、没有防回滚保护**；清单来源的可信性不由本工具保证。
- `replay_status=PASS` 表示用当前规则包重算判定后与记录语义一致（比对忽略重新分配的判定 ID）。
- 清单会记录本次运行真实使用的规则包摘要 `rule_sm3`；规则实现一变，旧包的重放会被拒绝，
  而不是拿占位摘要冒充「规则已验证」。

## 材料来源与安全

- 仓库里的 `examples/materials/` 是**合成演示材料**，只含证书、不含任何私钥，由
  `tools/make_demo_materials.py` 生成。
- ⚠️ **不要为了改 `case.json` 重跑该脚本**：`cryptography` 每次生成新的随机密钥，
  会把已提交的证书内容改掉（SM3 全变），影响所有人的复现结果。改元数据请直接编辑 JSON。
- `.gitignore` 默认忽略 `*.pem` / `*.der`，`examples/materials/` 靠显式豁免入库；
  新增证书材料后确认它真的被跟踪（`git ls-files examples/materials`）。

## 更多文档

| 文件 | 内容 |
|---|---|
| [从这里开始.md](../从这里开始.md) | 接手这个项目先读什么、已知的坑、下一步待办 |
| [开发协作与代码规范.md](开发协作与代码规范.md) | 三人的模块边界、共享契约变更规则、规则包约定 |
| [一阶段整合报告.md](一阶段整合报告.md) | 解析、证据、判定、报告、证据包、核验 |
| [二阶段进展报告.md](二阶段进展报告.md) | 16 条风险规则、规则重放 |
| [三阶段进展报告.md](三阶段进展报告.md) | 版本化规则包、49 项标准指标目录、判定侧扩展 |
| [任务对接.md](任务对接.md) | 跨模块待确认项 |

## 协作约定

每人从 `main` 建短期分支。公开字段、必填性或接口语义改变时，同一次提交更新共享类、
两组样例、测试和协作规范（当前契约版本 `0.2.1-mvp`），并请另外两人复核。**不要**把私钥、
导入的原始材料、运行数据库或生成报告提交到仓库。
