"""持久化层：追加式哈希链事件日志 + 逐签封/锁/撤销文件 + 清单。

约束（对应题面“依据实际落盘的签封及清单重建”）：

* 每条写入都 **flush + os.fsync**，保证落盘而非停在页缓存；
* 事件日志是哈希链，恢复时先校验链完整，任何篡改/断裂都暴露；
* 签封、锁、撤销各自单独成文件，恢复时把这些**独立文件**与清单交叉核对，
  不允许只信日志或只信清单；
* 多线程安全：所有变更在实例级 threading.Lock 下串行化。
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Callable, Iterator

from .canonical import sha256_hex
from .model import (
    Event,
    Lock,
    Manifest,
    Revoke,
    ReRoot,
    Seal,
)


class StoreCorruption(RuntimeError):
    """落盘数据无法通过完整性校验。"""


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """写临时文件 -> fsync -> 原子替换 -> fsync 目录（尽力而为）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def _fsync_dir(directory: Path) -> None:
    """在支持目录 fsync 的平台上同步目录项（Windows 上通常不支持，忽略）。"""
    if os.name == "nt":  # Windows 无法对目录句柄 fsync
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _dumps(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


class Store:
    """一个许可批次的工作目录。"""

    EVENTS = "events.jsonl"
    MANIFEST = "manifest.json"
    LOCKS = "locks"
    SEALS = "seals"
    REVOKES = "revokes"
    REROOTS = "reroots"

    def __init__(self, root: str | os.PathLike) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        for sub in (self.LOCKS, self.SEALS, self.REVOKES, self.REROOTS):
            (self.root / sub).mkdir(exist_ok=True)
        self._lock = threading.Lock()
        self._events_path = self.root / self.EVENTS
        self._last_event: Event | None = None
        self._load_chain_tail()

    # ------------------------------------------------------------------ #
    # 事件日志
    # ------------------------------------------------------------------ #
    def _load_chain_tail(self) -> None:
        if not self._events_path.exists():
            self._last_event = None
            return
        last = None
        for ev in self.iter_events():
            last = ev
        self._last_event = last

    def iter_events(self) -> Iterator[Event]:
        """逐行解析并校验哈希链。链断裂即报错。"""
        if not self._events_path.exists():
            return
        prev_hash = ""
        expected_seq = 0
        with open(self._events_path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise StoreCorruption(f"事件行 {lineno} 非法 JSON: {exc}") from exc
                ev = Event.from_dict(d)
                if ev.seq != expected_seq:
                    raise StoreCorruption(
                        f"事件行 {lineno} 序号跳变: 期望 {expected_seq} 实得 {ev.seq}"
                    )
                if ev.prev_hash != prev_hash:
                    raise StoreCorruption(f"事件行 {lineno} prev_hash 不衔接")
                if ev.compute_hash() != ev.hash:
                    raise StoreCorruption(f"事件行 {lineno} 自哈希不符")
                prev_hash = ev.hash
                expected_seq += 1
                yield ev

    def append_event(self, etype: str, payload: dict) -> Event:
        """线程安全追加事件，fsync 后返回。"""
        return self.append_event_built(etype, lambda seq: payload)

    def append_event_built(self, etype: str, build: "Callable[[int], dict]") -> Event:
        """原子地先分配 seq，再据 seq 构造 payload 并落盘。

        这样实体里携带的 created_seq 与事件日志中的 seq **在同一个临界区**
        内保持一致，不会因“先 next_seq 再 append”之间的竞态而错位。
        """
        with self._lock:
            seq = 0 if self._last_event is None else self._last_event.seq + 1
            prev = "" if self._last_event is None else self._last_event.hash
            payload = build(seq)
            ev = Event(seq, etype, payload, prev).sealed()
            with open(self._events_path, "ab") as f:
                f.write(_dumps(ev.to_dict()) + b"\n")
                f.flush()
                os.fsync(f.fileno())
            self._last_event = ev
            return ev

    def next_seq(self) -> int:
        with self._lock:
            return 0 if self._last_event is None else self._last_event.seq + 1

    # ------------------------------------------------------------------ #
    # 独立事实文件
    # ------------------------------------------------------------------ #
    def write_lock(self, lock: Lock) -> Path:
        # 文件名包含代与序号，保证多次锁（轮换/换根）各自留存，供恢复与代回退检测
        p = self.root / self.LOCKS / (
            f"{_safe(lock.permit_no)}.g{lock.generation}.s{lock.created_seq}.json"
        )
        _atomic_write_bytes(p, _dumps(lock.to_dict()))
        return p

    def write_seal(self, seal: Seal) -> Path:
        d = seal.payload.digest()
        p = self.root / self.SEALS / f"{d}.json"
        _atomic_write_bytes(p, _dumps(seal.to_dict()))
        return p

    def write_revoke(self, rev: Revoke) -> Path:
        target = _safe(rev.target)
        gen = "all" if rev.generation is None else str(rev.generation)
        p = self.root / self.REVOKES / f"{target}.g{gen}.s{rev.created_seq}.json"
        _atomic_write_bytes(p, _dumps(rev.to_dict()))
        return p

    def write_reroot(self, rr: ReRoot) -> Path:
        p = self.root / self.REROOTS / f"{_safe(rr.new_root)}.s{rr.created_seq}.json"
        _atomic_write_bytes(p, _dumps(rr.to_dict()))
        return p

    def write_manifest(self, manifest: Manifest) -> Path:
        p = self.root / self.MANIFEST
        _atomic_write_bytes(p, _dumps(manifest.to_dict()))
        return p

    # ------------------------------------------------------------------ #
    # 读取独立事实
    # ------------------------------------------------------------------ #
    def read_locks(self) -> list[Lock]:
        out = []
        for p in sorted((self.root / self.LOCKS).glob("*.json")):
            out.append(Lock.from_dict(json.loads(p.read_text("utf-8"))))
        return out

    def read_seals(self) -> list[Seal]:
        out = []
        for p in sorted((self.root / self.SEALS).glob("*.json")):
            d = json.loads(p.read_text("utf-8"))
            seal = Seal.from_dict(d)
            if seal.payload.digest() != p.stem:
                raise StoreCorruption(f"签封文件名与内容摘要不符: {p.name}")
            if d.get("digest") != seal.payload.digest():
                raise StoreCorruption(f"签封信封摘要字段不符: {p.name}")
            out.append(seal)
        return out

    def read_revokes(self) -> list[Revoke]:
        out = []
        for p in sorted((self.root / self.REVOKES).glob("*.json")):
            out.append(Revoke.from_dict(json.loads(p.read_text("utf-8"))))
        return out

    def read_reroots(self) -> list[ReRoot]:
        out = []
        for p in sorted((self.root / self.REROOTS).glob("*.json")):
            out.append(ReRoot.from_dict(json.loads(p.read_text("utf-8"))))
        return out

    def read_manifest(self) -> Manifest | None:
        p = self.root / self.MANIFEST
        if not p.exists():
            return None
        d = json.loads(p.read_text("utf-8"))
        m = Manifest.from_dict(d)
        if m.digest() != d.get("digest"):
            raise StoreCorruption("清单自摘要不符")
        return m

    # ------------------------------------------------------------------ #
    # 目录信息（证据重算需要）
    # ------------------------------------------------------------------ #
    def seal_path_by_digest(self, digest: str) -> Path:
        return self.root / self.SEALS / f"{digest}.json"

    def events_digest(self) -> str:
        return sha256_hex(self._events_path.read_bytes()) if self._events_path.exists() else ""


def _safe(name: str) -> str:
    """把任意标识转成安全文件名片段。"""
    out = []
    for ch in name:
        if ch.isalnum() or ch in "-_.":
            out.append(ch)
        else:
            out.append(f"%{ord(ch):02x}")
    s = "".join(out)
    if not s or s in {".", ".."}:
        s = "_"
    return s
