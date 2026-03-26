import json
import os
import threading
from typing import List, Optional
from phase2.app.models import User

JSON_FILE_PATH = "/workspace/phase2/users.json"


class JSONStore:
    def __init__(self, file_path: str = JSON_FILE_PATH):
        self.file_path = file_path
        self._lock = threading.Lock()
        self._init_file()

    def _init_file(self):
        """Creates the JSON file with an empty list if it doesn't exist."""
        if not os.path.exists(self.file_path):
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump([], f)

    def _load_all(self) -> List[dict]:
        with open(self.file_path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []

    def _save_all(self, data: List[dict]):
        with open(self.file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def get_user_by_username(self, username: str) -> Optional[User]:
        with self._lock:
            users_data = self._load_all()
            for u in users_data:
                if u.get("username") == username:
                    return User(**u)
        return None

    def add_user(self, username: str, hashed_password: str, totp_secret: str) -> User:
        with self._lock:
            users_data = self._load_all()
            
            # Auto-increment ID
            new_id = 1
            if users_data:
                new_id = max(u.get("id", 0) for u in users_data) + 1
                
            new_user = User.create(
                user_id=new_id,
                username=username,
                hashed_password=hashed_password,
                totp_secret=totp_secret
            )
            
            users_data.append(new_user.__dict__)
            self._save_all(users_data)
            return new_user


# Global store instance
store = JSONStore(JSON_FILE_PATH)


def get_db():
    """Dependency injection wrapper (returns the store instead of DB session)."""
    yield store

