import ftplib
import logging
import os
import secrets
import tempfile
import threading
import time

from collections import defaultdict, deque
from contextlib import contextmanager
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
from file_records import FileRecords
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
ACTIVITY_LABELS = {
    "upload": "Добавил файл",
    "folder": "Создал папку",
    "delete": "Переместил в корзину",
    "restore": "Восстановил из корзины",
    "purge": "Удалил навсегда",
    "rename": "Переименовал",
    "share": "Создал общую ссылку",
    "unshare": "Отключил общую ссылку",
}


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
    records = FileRecords(database)

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
        records=records,
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

    def auth_next(value):
        try:
            target = urlsplit(value)
        except ValueError:
            return ""
        if (
            not target.scheme and not target.netloc
            and target.path.startswith("/s/")
            and not any(ord(character) < 32 for character in value)
        ):
            return value
        return ""

    def page(mode, **values):
        values.setdefault("shared", None)
        values.setdefault("sort", "name")
        values.setdefault("next_url", auth_next(request.values.get("next", "")))
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
            activity_labels=ACTIVITY_LABELS,
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

    def entries(client, path, sort="name"):
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
                        "extension": (
                            name.rsplit(".", 1)[-1].casefold()
                            if facts["type"] == "file" and "." in name else ""
                        ),
                        "size": int(
                            facts.get("size", 0)
                        ),
                    }
                )

        return sorted(
            result,
            key=lambda entry: (
                entry["type"] != "dir",
                entry["extension"] if sort == "type"
                else entry["size"] if sort == "size" else "",
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

    def selected_entry(client, path):
        if path == "/":
            raise ValueError("Выберите файл или папку, а не корневой каталог.")
        parent, name = path.rsplit("/", 1)
        selected = next((item for item in entries(client, parent or "/")
                         if item["name"] == name), None)
        if selected is None:
            abort(404, description="Файл или папка не найдены.")
        return selected

    def selected_sort():
        value = request.args.get("sort", "name")
        return value if value in {"name", "type", "size"} else "name"

    def download_file(owner, path):
        if path == "/":
            raise ValueError("Выберите файл.")
        output = tempfile.SpooledTemporaryFile(max_size=1048576, mode="w+b")
        try:
            with storage.lock(owner["id"]), storage.connect(owner) as client:
                client.retrbinary("RETR " + path, output.write)
            size = output.tell()
            output.seek(0)
            response = send_file(
                output, as_attachment=True,
                download_name=path.rsplit("/", 1)[-1],
                mimetype="application/octet-stream", conditional=False,
            )
            response.content_length = size
            response.call_on_close(output.close)
            return response
        except Exception:
            output.close()
            raise

    @contextmanager
    def shared_access(token):
        need_user()
        shared = records.share(token)
        if shared is None:
            abort(404, description="Ссылка недействительна или доступ отключён.")
        with storage.lock(shared["owner_id"]):
            # Recheck after acquiring the lock: the owner may have revoked it.
            shared = records.share(token)
            if shared is None:
                abort(404, description="Доступ по ссылке отключён.")
            owner = database.get(shared["owner_id"])
            storage.usage(owner)  # Reject symbolic links, as in the private file view.
            yield shared, owner

    def shared_path(shared, relative):
        relative = safe_path(relative)
        return safe_path(shared["path"] + (relative if relative != "/" else ""))

    def purge_tree(client, path):
        for name, facts in list(client.mlsd(path)):
            if facts.get("type") not in {"file", "dir"}:
                continue
            # Interrupted uploads can leave an internal .upload-* file.
            safe_name(name[1:] if name.startswith(".") else name)
            child = path + "/" + name
            if facts["type"] == "dir":
                purge_tree(client, child)
            else:
                client.delete(child)
        client.rmd(path)

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
                    "script-src 'self'; "
                    "style-src 'self' 'unsafe-inline'; "
                    "object-src 'none'; "
                    "base-uri 'none'; "
                    "frame-ancestors 'none'; "
                    "form-action 'self'"
                ),
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "same-origin",
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
                "Операция с файлом не выполнена. "
                "Проверьте, что файл и родительская папка существуют."
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

        if request.args.get("tab") == "trash":
            return page("trash", items=records.trash_items(g.user["id"]))

        if request.args.get("tab") == "history":
            number = max(1, min(1000000, request.args.get("page", 1, type=int) or 1))
            events = records.history(g.user["id"], (number - 1) * 50)
            return page("history", events=events[:50], number=number, more=len(events) > 50)

        if request.args.get("tab") == "shared":
            return page(
                "shared", own_shares=records.own_shares(g.user["id"]),
                received_shares=records.received_shares(g.user["id"]),
                created=request.args.get("created", ""),
            )

        path = safe_path(
            request.args.get("path", "/")
        )

        with (
            storage.lock(g.user["id"]),
            storage.connect(g.user) as client,
        ):
            files = entries(client, path, selected_sort())
            used = storage.usage(g.user)[0]

        return page(
            "files",
            path=path,
            parent=path.rsplit("/", 1)[0] or "/",
            files=files,
            used=round(used / 1048576, 2),
            sort=selected_sort(),
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

        return redirect(auth_next(request.form.get("next", "")) or url_for("index"))

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
            try:
                records.log(user, "folder", target)
            except Exception:
                client.rmd(target)
                raise

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
                    try:
                        records.log(user, "upload", target)
                    except Exception:
                        client.delete(target)
                        raise

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
        return download_file(user, safe_path(request.args.get("path", "")))

    @app.post("/delete")
    def delete():
        user = need_user()
        path = safe_path(request.form.get("path", ""))
        parent, name = path.rsplit("/", 1)
        with (
            storage.lock(user["id"]),
            storage.connect(user) as client,
        ):
            selected = selected_entry(client, path)
            try:
                client.cwd("/.trash")
            except ftplib.error_perm:
                client.mkd("/.trash")
            item_id = secrets.token_hex(16)
            destination = "/.trash/" + item_id
            client.rename(path, destination)
            try:
                records.add_trash(user, item_id, path, selected["type"])
            except Exception:
                client.rename(destination, path)
                raise
        flash("Перемещено в корзину. Файл или папку можно восстановить.")
        return redirect(url_for("index", path=parent or "/"))

    @app.post("/rename")
    def rename():
        user = need_user()
        path = safe_path(request.form.get("path", ""))
        name = safe_name(request.form.get("name", ""))
        parent = path.rsplit("/", 1)[0] or "/"
        destination = join_path(parent, name)
        with storage.lock(user["id"]), storage.connect(user) as client:
            selected = selected_entry(client, path)
            if destination == path:
                return redirect(url_for("index", path=parent))
            if any(item["name"].casefold() == name.casefold()
                   and join_path(parent, item["name"]) != path
                   for item in entries(client, parent)):
                raise ValueError("Файл или папка с таким именем уже существует.")
            client.rename(path, destination)
            try:
                records.rename(user, path, destination, is_folder=selected["type"] == "dir")
            except Exception:
                client.rename(destination, path)
                raise
        flash("Название изменено.")
        return redirect(url_for("index", path=parent))

    @app.post("/trash/<item_id>/restore")
    def restore(item_id):
        user = need_user()
        with storage.lock(user["id"]), storage.connect(user) as client:
            item = records.trash_item(user["id"], item_id)
            if item is None:
                abort(404, description="Объект в корзине не найден.")
            path = safe_path(item["original_path"])
            parent, name = path.rsplit("/", 1)
            try:
                siblings = entries(client, parent or "/")
            except ftplib.error_perm:
                raise ValueError("Исходная папка отсутствует. Сначала восстановите её из корзины.")
            if any(entry["name"].casefold() == name.casefold() for entry in siblings):
                raise ValueError("По исходному пути уже есть объект с таким именем. Переименуйте его перед восстановлением.")
            source = "/.trash/" + item["id"]
            client.rename(source, path)
            try:
                records.finish_trash(user, item, "restore")
            except Exception:
                client.rename(path, source)
                raise
        flash("Восстановлено в исходную папку.")
        return redirect(url_for("index", tab="trash"))

    @app.post("/trash/<item_id>/purge")
    def purge(item_id):
        user = need_user()
        with storage.lock(user["id"]), storage.connect(user) as client:
            storage.usage(user)  # Never follow filesystem links while removing a tree.
            item = records.trash_item(user["id"], item_id)
            if item is None:
                abort(404, description="Объект в корзине не найден.")
            source = "/.trash/" + item["id"]
            if item["kind"] == "dir":
                purge_tree(client, source)
            else:
                client.delete(source)
            records.finish_trash(user, item, "purge")
        flash("Удалено навсегда.")
        return redirect(url_for("index", tab="trash"))

    @app.post("/share")
    def share():
        user = need_user()
        rate_limit(("share", user["id"]))
        path = safe_path(request.form.get("path", ""))
        with storage.lock(user["id"]), storage.connect(user) as client:
            if selected_entry(client, path)["type"] != "dir":
                raise ValueError("Поделиться можно только папкой.")
            token = records.create_share(user, path)
        flash("Ссылка создана. Доступны только просмотр и скачивание после входа.")
        return redirect(url_for("index", tab="shared", created=token))

    @app.post("/share/<token>/revoke")
    def revoke_share(token):
        user = need_user()
        with storage.lock(user["id"]):
            records.revoke_share(user, token)
        flash("Доступ по ссылке отключён.")
        return redirect(url_for("index", tab="shared"))

    @app.get("/s/<token>")
    def shared_folder(token):
        if not g.user:
            return redirect(url_for("index", next=request.full_path.rstrip("?")))
        relative = safe_path(request.args.get("path", "/"))
        with shared_access(token) as (shared, owner):
            with storage.connect(owner) as client:
                files = entries(client, shared_path(shared, relative), selected_sort())
            records.remember_share(g.user["id"], token)
            return page(
                "shared_files", shared=shared, files=files, path=relative,
                parent=relative.rsplit("/", 1)[0] or "/", sort=selected_sort(),
            )

    @app.get("/s/<token>/download")
    def shared_download(token):
        if not g.user:
            return redirect(url_for("index", next=request.full_path.rstrip("?")))
        relative = safe_path(request.args.get("path", "/"))
        if relative == "/":
            raise ValueError("Выберите файл.")
        with shared_access(token) as (shared, owner):
            return download_file(owner, shared_path(shared, relative))

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
