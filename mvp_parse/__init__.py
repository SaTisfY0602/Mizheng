"""成员一模块（已按共享契约适配）：材料解析与证据整理。

本包把成员一交付的解析逻辑接到共享契约 `0.2.0-mvp` 上。原始交付位于
`复赛/member 1/`，其中：

* `member1_parser.py` 的 X.509 字段提取逻辑被保留（见 `x509_certificate.py`）；
* `member1_evidence_builder.py` 是 0 字节空文件，`EvidenceBuilder` 由本包补齐；
* 交付时自带的 `mvp_contracts/` 是第二套字段命名完全不同的契约，**未**并入本仓库，
  统一使用仓库的共享契约。

适配时修正的三处接口问题（协作规范 §3.5、§3.6、§4）：

1. `storage_key` 经 `mvp_flow.storage.MaterialStore` 解析，不再对调用方给的路径直接
   `open()`；
2. ID 由注入的 `IdAllocator` 分配，不再用 `uuid4`；
3. 参考时间取 `ParseRequest.scope.as_of`，不读执行当天时间。
"""

from .evidence import EvidenceBuilder, EvidenceBuildError, derive_binding_candidates
from .nginx_config import NginxConfigParser
from .x509_certificate import X509CertificateParser

__all__ = [
    "EvidenceBuildError",
    "EvidenceBuilder",
    "NginxConfigParser",
    "X509CertificateParser",
    "derive_binding_candidates",
]
