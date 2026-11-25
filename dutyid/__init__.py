"""dutyid — 离线值班身份签发安全复核工具 (Python 3.12 标准库).

模块分层（越低层越可信，验签器只依赖底部两层）:

    canonical  规范 JSON + 哈希
    crypto     合成根密钥、HMAC 签封、根来源独立性判定
    model      数据模型（事件 / 签封 / 记录）
    store      持久化：哈希链事件日志 + 逐签封文件 + 清单（全部 fsync）
    engine     状态机：锁授权、签封、签发、撤销、代理换根；恢复重建授权集合
    evidence   最小冲突证据（极小不可满足子集）构造与包装
    verify     独立验签器：只依赖 canonical + crypto，重算一切
    scenarios  两个真实线程 + 屏障的竞态复现（撤销先写入 / 回执遗失后旧代重投）
    modelcheck 小图穷举签发·撤销·代理换根的短交错
    scale      六万条按组织隔离的身份记录，比较单次撤回访问范围 vs 全量结果
"""

__version__ = "1.0.0"
