"""成员三提供的受控材料存储层。

协作规范 §4 约定：``ParseRequest.artifact.storage_key`` **只由受控存储层解释**；
不得拿上传文件名拼本地路径或命令。本模块就是这条约定的落地实现，9 月 28 日交付
清单里「成员三约定受控材料存储入口」指的就是它。

三条硬约定
----------
1. ``storage_key`` 形如 ``<项目号>/<材料号>``，**只能**由 :meth:`MaterialStore.storage_key_for`
   生成；调用方不得自行拼接。原始文件名只作为 ``Artifact.original_name`` 元数据保留，
   不参与任何路径计算。
2. 导入是一次性写入：目标位置已有材料就拒绝，不静默覆盖（协作规范要求历史材料
   只追加或新建版本）。
3. :meth:`MaterialStore.resolve` 会拒绝绝对路径、盘符、反斜线、``..`` 和目录穿越，
   解析结果必须仍位于存储根目录内。

本层不生成 ID：``artifact_id`` 由成员三的 ``IdAllocator`` 分配后传入；导入时现算
SM3 与字节数，成员一直接拿去构造 ``Artifact`` 即可。
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from .digest import sm3_of_file
from .id_allocator import IdAllocatorError, require_identifier

_KEY_FORBIDDEN = ("\\", ":")
_NAME_FORBIDDEN = ("/", "\\", ":")


@dataclass(frozen=True)
class StoredMaterial:
    """一次成功导入的结果，用于构造共享契约里的 ``Artifact``。"""

    storage_key: str
    original_name: str
    sm3: str
    byte_size: int


class MaterialStorageError(RuntimeError):
    """材料无法安全导入或解析时抛出。"""


class MaterialStore:
    """按项目分目录存放材料，只暴露 ``storage_key`` 作为对外的材料引用。"""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        self._root = self._root.resolve()

    @property
    def root(self) -> Path:
        """存储根目录的绝对路径；只用于诊断，不交给调用方拼路径。"""
        return self._root

    def storage_key_for(self, *, project_id: str, artifact_id: str) -> str:
        """生成材料引用；这是唯一允许产生 ``storage_key`` 的地方。"""
        return (
            f"{require_identifier(project_id, 'project_id')}"
            f"/{require_identifier(artifact_id, 'artifact_id')}"
        )

    def import_material(
        self,
        *,
        project_id: str,
        artifact_id: str,
        original_name: str,
        source: Path,
    ) -> StoredMaterial:
        """把一份材料复制进受控目录，返回其引用、真实 SM3 与字节数。"""
        _require_safe_original_name(original_name)
        source_path = Path(source)
        if not source_path.is_file():
            raise MaterialStorageError(f"待导入材料不是普通文件：{source_path}")

        storage_key = self.storage_key_for(
            project_id=project_id, artifact_id=artifact_id
        )
        target = self._root / storage_key
        if target.exists():
            raise MaterialStorageError(f"目标位置已有材料，拒绝覆盖：{storage_key}")

        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target)

        return StoredMaterial(
            storage_key=storage_key,
            original_name=original_name,
            sm3=sm3_of_file(target),
            byte_size=target.stat().st_size,
        )

    def resolve(self, storage_key: str) -> Path:
        """把 ``storage_key`` 解析为受控目录内的真实路径，越界即拒绝。"""
        _require_safe_storage_key(storage_key)
        candidate = (self._root / storage_key).resolve()
        if not candidate.is_relative_to(self._root):
            raise MaterialStorageError(f"storage_key 越出存储根目录：{storage_key!r}")
        if not candidate.is_file():
            raise MaterialStorageError(f"材料不存在或不是普通文件：{storage_key!r}")
        return candidate

    def exists(self, storage_key: str) -> bool:
        """判断材料是否存在；不合法或越界一律按不存在处理。"""
        try:
            self.resolve(storage_key)
        except MaterialStorageError:
            return False
        return True


def _require_safe_storage_key(storage_key: str) -> None:
    if not isinstance(storage_key, str) or not storage_key.strip():
        raise MaterialStorageError("storage_key 不能为空")
    if storage_key.startswith(("/", "\\")) or any(
        forbidden in storage_key for forbidden in _KEY_FORBIDDEN
    ):
        raise MaterialStorageError(
            f"storage_key 必须是相对路径，且不含反斜线或盘符：{storage_key!r}"
        )
    parts = storage_key.split("/")
    if len(parts) < 2 or any(part in {"", ".", ".."} for part in parts):
        raise MaterialStorageError(
            f"storage_key 必须是 <项目号>/<材料号> 形式的安全相对路径：{storage_key!r}"
        )
    try:
        for part in parts:
            require_identifier(part, "storage_key 片段")
    except IdAllocatorError as exc:
        raise MaterialStorageError(str(exc)) from exc


def _require_safe_original_name(original_name: str) -> None:
    """原始文件名只作元数据；带路径分隔符就拒绝，避免下游误当路径使用。"""
    if not isinstance(original_name, str) or not original_name.strip():
        raise MaterialStorageError("original_name 不能为空")
    if any(separator in original_name for separator in _NAME_FORBIDDEN):
        raise MaterialStorageError(
            f"原始文件名不能包含路径分隔符：{original_name!r}"
        )
    if original_name in {".", ".."}:
        raise MaterialStorageError(f"原始文件名不合法：{original_name!r}")
