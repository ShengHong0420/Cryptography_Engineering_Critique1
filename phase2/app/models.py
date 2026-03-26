from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class User:
    id: int
    username: str
    hashed_password: str
    totp_secret: str
    created_at: str  # Stored as ISO-8601 string in JSON

    @classmethod
    def create(cls, user_id: int, username: str, hashed_password: str, totp_secret: str) -> "User":
        return cls(
            id=user_id,
            username=username,
            hashed_password=hashed_password,
            totp_secret=totp_secret,
            created_at=datetime.utcnow().isoformat()
        )

