from collections import defaultdict
from typing import Generic, TypeVar
from .models import AnalysisRun, Finding, Project, Rule, User

T = TypeVar("T")


class InMemoryRepository(Generic[T]):
    def __init__(self):
        self.items: dict[str, T] = {}

    def add(self, item: T, key: str) -> T:
        self.items[key] = item
        return item

    def get(self, key: str) -> T | None:
        return self.items.get(key)

    def all(self) -> list[T]:
        return list(self.items.values())


class Repositories:
    def __init__(self):
        self.users = InMemoryRepository[User]()
        self.projects = InMemoryRepository[Project]()
        self.rules = InMemoryRepository[Rule]()
        self.runs = InMemoryRepository[AnalysisRun]()
        self.findings = InMemoryRepository[Finding]()
        self.project_members: dict[str, set[str]] = defaultdict(set)

    def user_by_username(self, username: str) -> User | None:
        return next((u for u in self.users.all() if u.username == username), None)

    def project_runs(self, project_id: str) -> list[AnalysisRun]:
        return [r for r in self.runs.all() if r.project_id == project_id]

    def run_findings(self, run_id: str) -> list[Finding]:
        return [f for f in self.findings.all() if f.run_id == run_id]
