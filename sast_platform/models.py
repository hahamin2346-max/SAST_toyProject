from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid


def now() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, Enum):
    ADMIN = "ADMIN"
    USER = "USER"


class RunStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass
class User:
    user_id: str
    username: str
    password_hash: str
    role: Role
    is_active: bool = True
    created_at: datetime = field(default_factory=now)
    updated_at: datetime = field(default_factory=now)
    last_login_at: datetime | None = None


@dataclass
class Project:
    project_id: str
    name: str
    description: str
    source_type: str
    target_language: str
    source_location: str
    created_by: str
    created_at: datetime = field(default_factory=now)
    updated_at: datetime = field(default_factory=now)


@dataclass
class Rule:
    rule_id: str
    rule_code: str
    name: str
    description: str
    category: str
    kisa_num: int | None
    reference_info: str | None
    default_severity: str
    is_active: bool = True


@dataclass
class AnalysisRun:
    run_id: str
    project_id: str
    executed_by: str
    analysis_mode: str
    language: str
    status: RunStatus = RunStatus.PENDING
    error_message: str | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    started_at: datetime | None = None
    ended_at: datetime | None = None


@dataclass
class Finding:
    finding_id: str
    run_id: str
    rule_id: str | None
    rule_code_snapshot: str
    rule_name_snapshot: str
    language: str
    severity: str
    confidence: float
    file_path: str
    line_number: int
    message: str
    evidence: str
    recommendation: str
    raw_result: dict[str, Any] = field(default_factory=dict)


def new_id() -> str:
    return str(uuid.uuid4())
