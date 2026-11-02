import re
import sqlite3
import threading
from contextlib import contextmanager

from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)


class Database:
    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()

        with self.connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('user', 'admin')),
                    active INTEGER NOT NULL DEFAULT 1,
                    version INTEGER NOT NULL DEFAULT 1
                )
                """
            )

    @contextmanager
    def connect(self):
        with self.lock:
            connection = sqlite3.connect(
                self.path,
                timeout=10,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")

            try:
                with connection:
                    yield connection
            finally:
                connection.close()

    def users(self):
        with self.connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM users ORDER BY id"
                )
            ]

    def get(self, user_id):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()

            return dict(row) if row else None

    def authenticate(self, username, password):
        if len(password) > 128:
            return None

        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if (
            row
            and row["active"]
            and check_password_hash(
                row["password_hash"],
                password,
            )
        ):
            return dict(row)

        return None

    def validate(self, username, password):
        if not re.fullmatch(
            r"[A-Za-z0-9_]{3,24}",
            username,
        ):
            raise ValueError(
                "Логин: от 3 до 24 латинских букв, "
                "цифр или знаков _."
            )

        if not 12 <= len(password) <= 128:
            raise ValueError(
                "Пароль: от 12 до 128 символов."
            )

    def create(self, username, password, first=False):
        self.validate(username, password)

        encoded = generate_password_hash(
            password,
            method="scrypt",
        )

        with self.connect() as connection:
            count = connection.execute(
                "SELECT count(*) FROM users"
            ).fetchone()[0]

            if first and count:
                raise ValueError(
                    "Администратор уже создан."
                )

            if not first and not count:
                raise ValueError(
                    "Сначала создайте администратора."
                )

            if count >= 100:
                raise ValueError(
                    "Максимум: 100 пользователей."
                )

            try:
                cursor = connection.execute(
                    """
                    INSERT INTO users(
                        username,
                        password_hash,
                        role
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        username,
                        encoded,
                        "admin" if first else "user",
                    ),
                )

            except sqlite3.IntegrityError as error:
                raise ValueError(
                    "Этот логин уже занят."
                ) from error

            user_id = cursor.lastrowid

        return self.get(user_id)

    def update(self, user_id, action, value):
        with self.connect() as connection:
            user = self.get(user_id)

            if not user:
                raise ValueError(
                    "Пользователь не найден."
                )

            if (
                action == "role"
                and value in {"admin", "user"}
            ):
                user["role"] = value

            elif (
                action == "active"
                and type(value) is bool
            ):
                user["active"] = int(value)

            elif action == "password":
                self.validate(
                    user["username"],
                    value,
                )

                user["password_hash"] = generate_password_hash(
                    value,
                    method="scrypt",
                )

            else:
                raise ValueError(
                    "Недопустимое действие."
                )

            others = connection.execute(
                """
                SELECT count(*)
                FROM users
                WHERE role = 'admin'
                  AND active = 1
                  AND id != ?
                """,
                (user_id,),
            ).fetchone()[0]

            if not others and not (
                user["active"]
                and user["role"] == "admin"
            ):
                raise ValueError(
                    "Нельзя отключить последнего администратора."
                )

            connection.execute(
                """
                UPDATE users
                SET role = ?,
                    active = ?,
                    password_hash = ?,
                    version = version + 1
                WHERE id = ?
                """,
                (
                    user["role"],
                    user["active"],
                    user["password_hash"],
                    user_id,
                ),
            )

        return self.get(user_id)
