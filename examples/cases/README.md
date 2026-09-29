# 外部案例演示集（`examples/cases/`）

这里是**给外部输入用的演示案例**，和 `examples/materials/` 不是一回事：

| 目录 | 用途 |
|---|---|
| `examples/materials/` | 仓库预置样例，给 `--all` 与回归测试用，案例名固定 |
| `examples/cases/` | **外部案例目录**，用 `--case-dir` 跑，演示「非预置输入」这条验收 |

为什么单独放一套：`examples/materials/` 的三组是「预置样例」，而 P0 验收要求
统一入口能处理**用户自己准备的**案例目录。这两类输入在流程里走的是同一条路径，
但验收时必须是不同来源，否则证明不了「非预置」。

## 三组案例

| 目录 | 期望结果 |
|---|---|
| `demo-bound/` | 绑定成立 → `EVALUATED`，三条判定均 `COMPLIANT`，风险 0 条 |
| `demo-unbound/` | 配置指向不存在的证书 → `PENDING_EVIDENCE`，缺口 `MISSING_BINDING`，`proposed_label` 为空 |
| `demo-broken/` | 除正常材料外多一份损坏 PEM → `E_PARSE_FAILED` 记入解析错误，其余材料照常准入 |

三组都用了**全新的对象**（`PRJ-C01` / `PRJ-C02` / `PRJ-C03`，`WEB-01/02/03`），
与 `examples/materials/` 里的 `PRJ-001/002/003` 不重叠，所以它们确实是非预置输入。

## 怎么跑

```powershell
cd <仓库根>

# 正常绑定
.\.venv\Scripts\python.exe -m mvp_flow demo-bound --mode real `
    --case-dir examples\cases\demo-bound --out results-external --now 2026-10-01T02:00:00Z

# 缺绑定
.\.venv\Scripts\python.exe -m mvp_flow demo-unbound --mode real `
    --case-dir examples\cases\demo-unbound --out results-external --now 2026-10-01T02:00:00Z

# 损坏材料
.\.venv\Scripts\python.exe -m mvp_flow demo-broken --mode real `
    --case-dir examples\cases\demo-broken --out results-external --now 2026-10-01T02:00:00Z
```

产物落在 `results-external/<案例名>/runs/<run_id>/`，互不覆盖。

## 案例目录格式

```text
<案例目录>/
    case.json              必需：项目、环境、对象、链路、核查时间、规则版本
    nginx.conf             必需：配置（ssl_certificate 的文件名要与证书文件名对得上）
    <证书>.pem / .der      必需：证书材料
    review_events.json     可选：人工确认绑定；要绑定成立就得有
```

四个硬约束见 `README.md`。这里只强调最容易踩的两个：

1. `rule_version` 必须写当前规则包接受的版本（现在是 `0.3.0-mvp`），否则判定引擎显式拒绝。
2. `nginx.conf` 里 `ssl_certificate` 的**文件名**要和证书文件名一致 —— 代码靠 basename
   关联「配置里的证书路径」与「证书材料」。`demo-unbound` 就是故意让它对不上。

## 这套案例是演示脚手架

成员一准备的真实外部案例可以直接替换它们；格式一致即可。如果成员一给的案例在字段或
命名上有出入，以 `README.md` 的约定为准，并同步更新本目录，别让两处说法不一致。
