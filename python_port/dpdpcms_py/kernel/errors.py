from __future__ import annotations

from datetime import UTC, datetime


class ApiError(Exception):
    def __init__(self, status: int, error: str, message: str):
        super().__init__(message)
        self.status = status
        self.error = error
        self.message = message


def error_body(status: int, error: str, message: str, path: str) -> dict:
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "status": status,
        "error": error,
        "message": message,
        "path": path,
    }
