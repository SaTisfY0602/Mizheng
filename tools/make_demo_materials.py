"""生成真实链路演示用的合成材料（只生成证书，不保存任何私钥）。

产物提交进仓库，作为「真实解析」的固定输入：

```text
examples/materials/complete/          nginx.conf + app.pem + root-ca.pem + case.json + review_events.json
examples/materials/missing_binding/   nginx.conf + unbound.der + case.json
examples/materials/risky/             nginx.conf + legacy.pem + case.json + review_events.json
```

三份材料刻意造成三种情形：

* `complete`：配置里的 `ssl_certificate` 指向 `app.pem`，文件名能对上证书材料，
  证书因此带上对象，再配合人工确认事件，绑定成立；证书由根 CA 签发、有用途扩展、
  SAN 与 `server_name` 一致、密钥 2048 位，所以判定侧三条规则全部通过；
* `missing_binding`：配置指向 `unknown.pem`，而证书材料叫 `unbound.der`，对不上，
  证书没有对象，绑定无法确认，必须落到 `MISSING_BINDING` 缺口；
* `risky`：故意做差（弱协议 + 弱套件 + 1024 位密钥 + 临期 + 自签 + 无用途扩展 +
  SAN 不匹配）。它同时验证两件事——风险侧识别出多条风险；**且**判定侧对短密钥给出
  不符合、对缺失用途扩展停在待补证（`MISSING_CERTIFICATE_EVIDENCE`）。

`case.json` 里的 `rule_version` 必须属于版本化规则包 ``mvp_rules`` 接受的版本集合。
当前真实材料用规则包的当前版本 ``0.3.0-mvp``，该版本声明了全部三条判定规则；契约
样例（``examples/contracts/``）保留历史版本 ``demo-0.2.0``，只声明绑定与有效期一条。

注意：``cryptography`` 会为每次运行生成新的随机密钥，**重新运行本脚本会改变证书
内容**。仓库里的证书是提交进去的固定输入，不要为了改 `case.json` 而重跑整个脚本。

用法：``.venv\\Scripts\\python.exe tools/make_demo_materials.py``
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = ROOT / "examples" / "materials"

NOT_BEFORE = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
NOT_AFTER = datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

COMPLETE_CONFIG = """# 合成演示材料，非真实生产配置
server {
    listen 443 ssl;
    server_name app.example.cn;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate /etc/nginx/ssl/app.pem;
    ssl_certificate_key /etc/nginx/ssl/app.key;
}
"""

MISSING_BINDING_CONFIG = """# 合成演示材料，非真实生产配置
server {
    listen 443 ssl;
    server_name unknown.example.cn;

    ssl_protocols TLSv1.2 TLSv1.3;
    # 该路径对应的证书材料没有提供
    ssl_certificate /etc/nginx/ssl/unknown.pem;
}
"""

RISKY_CONFIG = """# 合成演示材料：故意启用弱协议与弱套件，用于验证风险识别
server {
    listen 443 ssl;
    server_name legacy.example.cn;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    # RC4 与 3DES 套件都是明确要淘汰的；!aNULL 是排除项，不应被判为弱套件
    ssl_ciphers RC4-SHA:DES-CBC3-SHA:HIGH:!aNULL;
    ssl_certificate /etc/nginx/ssl/legacy.pem;
    ssl_certificate_key /etc/nginx/ssl/legacy.key;
}
"""


def _new_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mizheng Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def _server_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def build_ca(
    common_name: str = "Mizheng Demo Root CA",
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """生成自签的演示根 CA，用来签发叶证书（只用于本地演示）。"""
    key = _new_key()
    name = _name(common_name)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate, key


def build_certificate(
    common_name: str,
    *,
    key_size: int = 2048,
    not_before: datetime = NOT_BEFORE,
    not_after: datetime = NOT_AFTER,
    signer: tuple[x509.Certificate, rsa.RSAPrivateKey] | None = None,
    san_names: list[str] | None = None,
    with_usage: bool = True,
) -> x509.Certificate:
    """生成证书。

    * ``signer`` 为 ``None`` 时自签（会触发 ``RISK-CERT-SELF-SIGNED``）；
    * ``san_names`` 为 ``None`` 时用 ``common_name``；传别的值可造域名不匹配；
    * ``with_usage=False`` 时不写 keyUsage / ExtendedKeyUsage，
      用于触发 ``RISK-CERT-PURPOSE-MISSING``。

    注意：``cryptography`` 50.x 拒绝用 SHA-1 签名（``UnsupportedAlgorithm``），
    所以这里造不出真实弱签名证书；``RISK-CERT-WEAK-SIGNATURE`` 规则改由单元测试
    直接构造准入事实来覆盖。
    """
    key = _new_key(key_size)
    subject = _name(common_name)
    issuer = signer[0].subject if signer is not None else subject
    signing_key = signer[1] if signer is not None else key

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    names = [common_name] if san_names is None else san_names
    if names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in names]),
            critical=False,
        )
    if with_usage:
        builder = builder.add_extension(_server_key_usage(), critical=True)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    return builder.sign(signing_key, hashes.SHA256())


def _write_case_metadata(directory: Path, metadata: dict, review_events: list[dict] | None) -> None:
    (directory / "case.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if review_events is not None:
        (directory / "review_events.json").write_text(
            json.dumps(review_events, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


def main() -> None:
    complete = OUTPUT_ROOT / "complete"
    complete.mkdir(parents=True, exist_ok=True)
    (complete / "nginx.conf").write_text(COMPLETE_CONFIG, encoding="utf-8")
    # 根 CA + 由它签发的叶证书：叶证书不是自签、有用途扩展、SAN 与 server_name 一致
    root_ca, root_key = build_ca()
    (complete / "root-ca.pem").write_bytes(
        root_ca.public_bytes(serialization.Encoding.PEM)
    )
    (complete / "app.pem").write_bytes(
        build_certificate("app.example.cn", signer=(root_ca, root_key)).public_bytes(
            serialization.Encoding.PEM
        )
    )
    _write_case_metadata(
        complete,
        {
            "project_id": "PRJ-001",
            "environment": "PROD",
            "asset_id": "APP-01",
            "link_id": "LINK-01",
            "evaluation_time": "2026-09-24T02:00:00Z",
            "rule_version": "0.3.0-mvp",
            "previous_snapshot_id": "NONE",
        },
        [
            {
                "action": "CONFIRM_BINDING",
                "target_predicate": "service_uses_certificate",
                "confirmed_asset_id": "APP-01",
                "actor_id": "reviewer-01",
                "reason": "现场确认 APP-01 的 nginx 使用该证书",
            }
        ],
    )

    missing = OUTPUT_ROOT / "missing_binding"
    missing.mkdir(parents=True, exist_ok=True)
    (missing / "nginx.conf").write_text(MISSING_BINDING_CONFIG, encoding="utf-8")
    (missing / "unbound.der").write_bytes(
        build_certificate("unbound.example.cn").public_bytes(serialization.Encoding.DER)
    )
    _write_case_metadata(
        missing,
        {
            "project_id": "PRJ-002",
            "environment": "PROD",
            "asset_id": "APP-02",
            "link_id": "LINK-02",
            "evaluation_time": "2026-09-24T03:00:00Z",
            "rule_version": "0.3.0-mvp",
            "previous_snapshot_id": "NONE",
        },
        None,
    )

    # 故意做差的第三组：弱协议 + 弱套件 + 短密钥 + 临期 + 自签 + 无用途 + 域名不匹配
    risky = OUTPUT_ROOT / "risky"
    risky.mkdir(parents=True, exist_ok=True)
    (risky / "nginx.conf").write_text(RISKY_CONFIG, encoding="utf-8")
    (risky / "legacy.pem").write_bytes(
        build_certificate(
            "legacy.example.cn",
            key_size=1024,
            not_after=datetime(2026, 10, 4, 23, 59, 59, tzinfo=timezone.utc),
            # SAN 与配置里的 server_name（legacy.example.cn）不一致
            san_names=["old.example.cn"],
            # 不写用途扩展
            with_usage=False,
        ).public_bytes(serialization.Encoding.PEM)
    )
    _write_case_metadata(
        risky,
        {
            "project_id": "PRJ-003",
            "environment": "PROD",
            "asset_id": "APP-03",
            "link_id": "LINK-03",
            "evaluation_time": "2026-09-24T04:00:00Z",
            "rule_version": "0.3.0-mvp",
            "previous_snapshot_id": "NONE",
        },
        [
            {
                "action": "CONFIRM_BINDING",
                "target_predicate": "service_uses_certificate",
                "confirmed_asset_id": "APP-03",
                "actor_id": "reviewer-01",
                "reason": "现场确认 APP-03 的 nginx 使用该证书",
            }
        ],
    )

    for directory in (complete, missing, risky):
        print(f"已生成 {directory.relative_to(ROOT)}")
        for path in sorted(directory.iterdir()):
            print(f"    {path.name:22} {path.stat().st_size} B")


if __name__ == "__main__":
    main()
