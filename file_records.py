"""SQLite records for the recycle bin, shared links and file activity."""

import secrets


def within(path, folder):
    # App names are case-insensitive, including on the Windows FTPS filesystem.
    return (path.casefold() == folder.casefold()
            or path.casefold().startswith(folder.rstrip("/").casefold() + "/"))


class FileRecords:
    def __init__(self, database):
        self.database = database
        with database.connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS trash (
                    id TEXT PRIMARY KEY,
                    owner_id INTEGER NOT NULL REFERENCES users(id),
                    original_path TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('file', 'dir')),
                    deleted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS shares (
                    token TEXT PRIMARY KEY,
                    owner_id INTEGER NOT NULL REFERENCES users(id),
                    path TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE UNIQUE INDEX IF NOT EXISTS active_share_path
                    ON shares(owner_id, path) WHERE active = 1;
                CREATE TABLE IF NOT EXISTS share_visits (
                    token TEXT NOT NULL REFERENCES shares(token),
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    PRIMARY KEY(token, user_id)
                );
                CREATE TABLE IF NOT EXISTS activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL REFERENCES users(id),
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    path TEXT NOT NULL,
                    new_path TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS activity_by_owner
                    ON activity(owner_id, id DESC);
            """)

    @staticmethod
    def _log(connection, user, action, path, new_path=""):
        connection.execute(
            """INSERT INTO activity(owner_id, actor, action, path, new_path)
               VALUES (?, ?, ?, ?, ?)""",
            (user["id"], user["username"], action, path, new_path),
        )

    def log(self, user, action, path, new_path=""):
        with self.database.connect() as connection:
            self._log(connection, user, action, path, new_path)

    def history(self, user_id, offset=0):
        with self.database.connect() as connection:
            return [dict(row) for row in connection.execute(
                """SELECT * FROM activity WHERE owner_id = ?
                   ORDER BY id DESC LIMIT 51 OFFSET ?""", (user_id, offset),
            )]

    def trash_items(self, user_id):
        with self.database.connect() as connection:
            return [dict(row) for row in connection.execute(
                """SELECT * FROM trash WHERE owner_id = ?
                   ORDER BY deleted_at DESC, rowid DESC""", (user_id,),
            )]

    def trash_item(self, user_id, item_id):
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM trash WHERE owner_id = ? AND id = ?",
                (user_id, item_id),
            ).fetchone()
            return dict(row) if row else None

    def add_trash(self, user, item_id, path, kind):
        with self.database.connect() as connection:
            connection.execute(
                """INSERT INTO trash(id, owner_id, original_path, kind)
                   VALUES (?, ?, ?, ?)""", (item_id, user["id"], path, kind),
            )
            if kind == "dir":
                self._revoke_under(connection, user, path)
            self._log(connection, user, "delete", path)

    def finish_trash(self, user, item, action):
        with self.database.connect() as connection:
            connection.execute(
                "DELETE FROM trash WHERE owner_id = ? AND id = ?",
                (user["id"], item["id"]),
            )
            self._log(connection, user, action, item["original_path"])

    def rename(self, user, old_path, new_path, is_folder=False):
        with self.database.connect() as connection:
            for row in connection.execute(
                "SELECT token, path FROM shares WHERE owner_id = ? AND active = 1",
                (user["id"],),
            ).fetchall():
                if within(row["path"], old_path):
                    connection.execute(
                        "UPDATE shares SET path = ? WHERE token = ?",
                        (new_path + row["path"][len(old_path):], row["token"]),
                    )
            for row in connection.execute(
                "SELECT id, original_path FROM trash WHERE owner_id = ?",
                (user["id"],),
            ).fetchall():
                if (is_folder and within(row["original_path"], old_path)
                        and row["original_path"].casefold() != old_path.casefold()):
                    connection.execute(
                        "UPDATE trash SET original_path = ? WHERE id = ?",
                        (new_path + row["original_path"][len(old_path):], row["id"]),
                    )
            self._log(connection, user, "rename", old_path, new_path)

    def _revoke_under(self, connection, user, path):
        for row in connection.execute(
            "SELECT token, path FROM shares WHERE owner_id = ? AND active = 1",
            (user["id"],),
        ).fetchall():
            if within(row["path"], path):
                connection.execute(
                    "UPDATE shares SET active = 0 WHERE token = ?", (row["token"],),
                )
                self._log(connection, user, "unshare", row["path"])

    def create_share(self, user, path):
        with self.database.connect() as connection:
            for row in connection.execute(
                "SELECT token, path FROM shares WHERE owner_id = ? AND active = 1",
                (user["id"],),
            ):
                if row["path"].casefold() == path.casefold():
                    return row["token"]
            token = secrets.token_urlsafe(32)
            connection.execute(
                "INSERT INTO shares(token, owner_id, path) VALUES (?, ?, ?)",
                (token, user["id"], path),
            )
            self._log(connection, user, "share", path)
            return token

    def share(self, token):
        with self.database.connect() as connection:
            row = connection.execute(
                """SELECT shares.*, users.username AS owner_name FROM shares
                   JOIN users ON users.id = shares.owner_id
                   WHERE shares.token = ? AND shares.active = 1 AND users.active = 1""",
                (token,),
            ).fetchone()
            return dict(row) if row else None

    def revoke_share(self, user, token):
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT path FROM shares WHERE token = ? AND owner_id = ? AND active = 1",
                (token, user["id"]),
            ).fetchone()
            if not row:
                raise ValueError("Ссылка не найдена.")
            connection.execute("UPDATE shares SET active = 0 WHERE token = ?", (token,))
            self._log(connection, user, "unshare", row["path"])

    def remember_share(self, user_id, token):
        with self.database.connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO share_visits(token, user_id) VALUES (?, ?)",
                (token, user_id),
            )

    def own_shares(self, user_id):
        with self.database.connect() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT * FROM shares WHERE owner_id = ? AND active = 1 ORDER BY created_at DESC",
                (user_id,),
            )]

    def received_shares(self, user_id):
        with self.database.connect() as connection:
            return [dict(row) for row in connection.execute(
                """SELECT shares.*, users.username AS owner_name FROM share_visits
                   JOIN shares ON shares.token = share_visits.token
                   JOIN users ON users.id = shares.owner_id
                   WHERE share_visits.user_id = ? AND shares.active = 1
                     AND users.active = 1 AND shares.owner_id != ?
                   ORDER BY shares.created_at DESC""", (user_id, user_id),
            )]
