"""运行期配置，全部可通过环境变量覆盖。"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    db_path: str = os.getenv("DATABASE_PATH", "/data/capabilities.db")
    root_principal: str = os.getenv("ROOT_PRINCIPAL", "root")
    root_hmac_secret: str = os.getenv(
        "ROOT_HMAC_SECRET", "dev-root-secret-change-me"
    )
    seed_demo_principals: bool = _as_bool(
        os.getenv("SEED_DEMO_PRINCIPALS"), default=True
    )


settings = Settings()
