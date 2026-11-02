import ftplib
import logging
import os
import secrets
import tempfile
import threading
import time

from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from waitress import serve
from werkzeug.exceptions import (
    HTTPException,
    SecurityError,
)

from database import Database
from storage import (
    Storage,
    join_path,
    safe_name,
    safe_path,
)


BASE = Path(__file__).resolve().parent

MAX_FILE = 20 * 1024 * 1024
QUOTA = 100 * 1024 * 1024
WEB_PORT = 8080


def create_app(directory=None):
    directory = Path(
        directory or BASE / "data"
    ).resolve()

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    directory.chmod(0o700)

    database = Database(
        directory / "accounts.sqlite3"
    )

    storage = Storage(
        directory,
        database,
    )

    attempts = defaultdict(deque)
    rate_lock = threading.Lock()

    app = Flask(__name__)

    app.config.update(
        SECRET_KEY=secrets.token_hex(32),
        MAX_CONTENT_LENGTH=MAX_FILE + 65536,
        MAX_FORM_MEMORY_SIZE=128 * 1024,
        MAX_FORM_PARTS=5,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=timedelta(
            minutes=30
        ),
        TRUSTED_HOSTS=[
            "127.0.0.1",
            "localhost",
        ],
    )

    app.extensions.update(
        database=database,
        storage=storage,
        attempts=attempts,
    )

    def rate_limit(key, limit=10):
        with rate_lock:
            now = time.monotonic()
            queue = attempts[key]

            while (
                queue
                and now - queue[0] >= 60
            ):
                queue.popleft()

            if len(queue) >= limit:
                abort(
                    429,
                    description=(
                        "Слишком много попыток. "
                        "Подождите одну минуту."
                    ),
                )

            queue.append(now)

    def page(mode, **values):
        return render_template(
            "page.html",
            mode=mode,
            user=getattr(g, "user", None),
            csrf=session.setdefault(
                "csrf",
                secrets.token_urlsafe(32),
            ),
            max_file=MAX_FILE // 1048576,
            quota=QUOTA // 1048576,
            join_path=join_path,
            **values,
        )

    def need_user(admin=False):
        if not g.user:
            abort(
                401,
                description=(
                    "Сначала войдите в аккаунт."
                ),
            )

        if admin and g.user["role"] != "admin":
            abort(
                403,
                description=(
                    "Доступ только для администратора."
                ),
            )

        return g.user

    def sign_in(user):
        session.clear()

        session.update(
            user_id=user["id"],
            version=user["version"],
            csrf=secrets.token_urlsafe(32),
        )

        session.permanent = True

    def entries(client, path):
        client.cwd(safe_path(path))
        result = []

        for name, facts in client.mlsd():
            if (
                not name.startswith(".")
                and facts.get("type") in {"dir", "file"}
            ):
                result.append(
                    {
                        "name": safe_name(name),
                        "type": facts["type"],
                        "size": int(
                            facts.get("size", 0)
                        ),
                    }
                )

        return sorted(
            result,
            key=lambda entry: (
                entry["type"] != "dir",
                entry["name"].casefold(),
            ),
        )

    def check_new(
        user,
        client,
        parent,
        name,
        size=0,
    ):
        used, count = storage.usage(user)

        if used + size > QUOTA or count >= 2000:
            raise ValueError(
                "Недостаточно места или достигнут предел: "
                "2000 файлов и папок."
            )

        if any(
            entry["name"].casefold() == name.casefold()
            for entry in entries(client, parent)
        ):
            raise ValueError(
                "Файл или папка с таким именем "
                "уже существует."
            )

    @app.before_request
    def protect():
        g.user = None

        if session.get("user_id"):
            user = database.get(
                session["user_id"]
            )

            if (
                user
                and user["active"]
                and user["version"]
                == session.get("version")
            ):
                g.user = user
            else:
                session.clear()

        session.setdefault(
            "csrf",
            secrets.token_urlsafe(32),
        )

        if request.method == "POST":
            origin = request.headers.get("Origin")

            if (
                origin
                and urlsplit(origin).netloc
                != request.host
            ):
                abort(
                    403,
                    description=(
                        "Запрос с другого сайта запрещён."
                    ),
                )

            if (
                request.headers.get("Sec-Fetch-Site")
                == "cross-site"
            ):
                abort(
                    403,
                    description=(
                        "Запрос с другого сайта запрещён."
                    ),
                )

            supplied = request.form.get(
                "csrf",
                "",
            ).encode("utf-8")

            expected = session["csrf"].encode("ascii")

            if not secrets.compare_digest(
                supplied,
                expected,
            ):
                abort(
                    403,
                    description=(
                        "Обновите страницу "
                        "и повторите действие."
                    ),
                )

    @app.after_request
    def headers(response):
        response.headers.update(
            {
                "Content-Security-Policy": (
                    "default-src 'self'; "
                    "script-src 'none'; "
                    "style-src 'self' 'unsafe-inline'; "
                    "object-src 'none'; "
                    "base-uri 'none'; "
                    "frame-ancestors 'none'; "
                    "form-action 'self'"
                ),
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
            }
        )

        return response

    @app.errorhandler(ValueError)
    def validation_error(error):
        return page(
            "error",
            error=str(error),
        ), 400

    @app.errorhandler(ftplib.Error)
    def ftp_error(error):
        return page(
            "error",
            error=(
                "Операция FTP не выполнена. "
                "Проверьте путь. "
                "Папку можно удалить только пустой."
            ),
        ), 400

    @app.errorhandler(HTTPException)
    def http_error(error):
        if isinstance(error, SecurityError):
            return (
                "Недопустимый адрес сервера.",
                400,
            )

        text = (
            "Файл слишком большой."
            if error.code == 413
            else error.description
        )

        return page(
            "error",
            error=text,
        ), error.code

    @app.errorhandler(Exception)
    def unexpected_error(error):
        logging.exception(
            "Application error"
        )

        return page(
            "error",
            error=(
                "Ошибка сервера. Проверьте окно запуска "
                "и свободное место на диске."
            ),
        ), 500

    @app.get("/")
    def index():
        if not database.users():
            return page("setup")

        if not g.user:
            return page(
                "register"
                if request.args.get("register")
                else "login"
            )

        if request.args.get("tab") == "users":
            need_user(admin=True)

            return page(
                "users",
                users=database.users(),
            )

        path = safe_path(
            request.args.get("path", "/")
        )

        with (
            storage.lock(g.user["id"]),
            storage.connect(g.user) as client,
        ):
            files = entries(client, path)
            used = storage.usage(g.user)[0]

        return page(
            "files",
            path=path,
            parent=path.rsplit("/", 1)[0] or "/",
            files=files,
            used=round(used / 1048576, 2),
        )

    @app.post("/account/<action>")
    def account_action(action):
        if action == "logout":
            session.clear()
            return redirect(url_for("index"))

        if action not in {
            "login",
            "register",
            "setup",
        }:
            abort(404)

        rate_limit(
            action,
            10 if action == "login" else 5,
        )

        username = request.form.get(
            "username",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        if action == "login":
            user = database.authenticate(
                username,
                password,
            )

            if not user:
                abort(
                    401,
                    description=(
                        "Неверный логин или пароль, "
                        "либо аккаунт отключён."
                    ),
                )

        else:
            if password != request.form.get(
                "repeat",
                "",
            ):
                raise ValueError(
                    "Пароли не совпадают."
                )

            user = database.create(
                username,
                password,
                first=action == "setup",
            )

            storage.home(user["id"])

        sign_in(user)

        return redirect(url_for("index"))

    @app.post("/password")
    def password():
        user = need_user()
        rate_limit("password")

        old_password = request.form.get(
            "old_password",
            "",
        )

        if not database.authenticate(
            user["username"],
            old_password,
        ):
            raise ValueError(
                "Неверный текущий пароль."
            )

        updated = database.update(
            user["id"],
            "password",
            request.form.get("password", ""),
        )

        sign_in(updated)

        flash("Пароль изменён.")

        return redirect(url_for("index"))

    @app.post("/folder")
    def folder():
        user = need_user()

        parent = safe_path(
            request.form.get("path", "/")
        )

        name = safe_name(
            request.form.get("name", "")
        )

        target = join_path(parent, name)

        with (
            storage.lock(user["id"]),
            storage.connect(user) as client,
        ):
            check_new(
                user,
                client,
                parent,
                name,
            )

            client.mkd(target)

        flash("Папка создана.")

        return redirect(
            url_for("index", path=parent)
        )

    @app.post("/upload")
    def upload():
        user = need_user()

        parent = safe_path(
            request.form.get("path", "/")
        )

        uploaded = request.files.get("file")

        if not uploaded or not uploaded.filename:
            raise ValueError(
                "Выберите файл."
            )

        name = safe_name(uploaded.filename)
        target = join_path(parent, name)

        with tempfile.SpooledTemporaryFile(
            max_size=1048576,
            mode="w+b",
        ) as snapshot:
            size = 0

            while chunk := uploaded.stream.read(65536):
                size += len(chunk)

                if size > MAX_FILE:
                    abort(413)

                snapshot.write(chunk)

            snapshot.seek(0)

            with (
                storage.lock(user["id"]),
                storage.connect(user) as client,
            ):
                check_new(
                    user,
                    client,
                    parent,
                    name,
                    size,
                )

                temporary = (
                    parent.rstrip("/")
                    + "/.upload-"
                    + secrets.token_hex(16)
                )

                try:
                    client.storbinary(
                        "STOR " + temporary,
                        snapshot,
                    )

                    client.rename(
                        temporary,
                        target,
                    )

                except Exception:
                    try:
                        client.delete(temporary)
                    except ftplib.all_errors:
                        pass
                    raise

        flash("Файл загружен.")

        return redirect(
            url_for("index", path=parent)
        )

    @app.get("/download")
    def download():
        user = need_user()

        path = safe_path(
            request.args.get("path", "")
        )

        if path == "/":
            raise ValueError(
                "Выберите файл."
            )

        output = tempfile.SpooledTemporaryFile(
            max_size=1048576,
            mode="w+b",
        )

        try:
            with (
                storage.lock(user["id"]),
                storage.connect(user) as client,
            ):
                client.retrbinary(
                    "RETR " + path,
                    output.write,
                )

            size = output.tell()
            output.seek(0)

            response = send_file(
                output,
                as_attachment=True,
                download_name=path.rsplit("/", 1)[-1],
                mimetype="application/octet-stream",
                conditional=False,
            )

            response.content_length = size
            response.call_on_close(output.close)

            return response

        except Exception:
            output.close()
            raise

    @app.post("/delete")
    def delete():
        user = need_user()

        path = safe_path(
            request.form.get("path", "")
        )

        if path == "/":
            raise ValueError(
                "Нельзя удалить корневую папку."
            )

        parent, name = path.rsplit("/", 1)

        with (
            storage.lock(user["id"]),
            storage.connect(user) as client,
        ):
            selected = next(
                (
                    entry
                    for entry in entries(
                        client,
                        parent or "/",
                    )
                    if entry["name"] == name
                ),
                None,
            )

            if selected is None:
                abort(
                    404,
                    description="Файл не найден.",
                )

            if selected["type"] == "dir":
                client.rmd(path)
            else:
                client.delete(path)

        flash("Удалено.")

        return redirect(
            url_for(
                "index",
                path=parent or "/",
            )
        )

    @app.post("/admin/create")
    def admin_create():
        need_user(admin=True)

        user = database.create(
            request.form.get(
                "username",
                "",
            ).strip(),
            request.form.get("password", ""),
        )

        storage.home(user["id"])

        flash("Пользователь создан.")

        return redirect(
            url_for("index", tab="users")
        )

    @app.post("/admin/<int:user_id>")
    def admin_update(user_id):
        need_user(admin=True)

        action = request.form.get("action")
        value = request.form.get("value", "")

        if action == "active":
            if value not in {"0", "1"}:
                raise ValueError(
                    "Недопустимый статус."
                )

            value = value == "1"

        database.update(
            user_id,
            action,
            value,
        )

        if user_id == g.user["id"]:
            session.clear()

            return redirect(
                url_for("index")
            )

        flash("Изменения сохранены.")

        return redirect(
            url_for("index", tab="users")
        )

    return app


if __name__ == "__main__":
    os.umask(0o077)

    logging.basicConfig(
        level=logging.WARNING
    )

    application = create_app()

    print(
        f"Ouvrir http://127.0.0.1:{WEB_PORT} "
        "dans le navigateur. Arret : Ctrl+C.",
        flush=True,
    )

    try:
        serve(
            application,
            host="127.0.0.1",
            port=WEB_PORT,
            threads=4,
            max_request_body_size=MAX_FILE + 65536,
            expose_tracebacks=False,
        )

    except KeyboardInterrupt:
        pass

    finally:
        application.extensions["storage"].close()