import hashlib
import hmac
import ipaddress
import secrets
import ssl
import threading
import unicodedata

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from ftplib import FTP_TLS

from cryptography import x509
from cryptography.hazmat.primitives import (
    hashes,
    serialization,
)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import SSL

from pyftpdlib.authorizers import (
    AuthenticationFailed,
    DummyAuthorizer,
)
from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.ioloop import IOLoop
from pyftpdlib.servers import FTPServer


def safe_name(name):
    name = unicodedata.normalize("NFC", name)

    reserved = {"CON", "PRN", "AUX", "NUL"}

    reserved.update(
        f"COM{number}"
        for number in range(1, 10)
    )

    reserved.update(
        f"LPT{number}"
        for number in range(1, 10)
    )

    if (
        not name
        or len(name) > 100
        or name.startswith(".")
        or name.endswith((".", " "))
        or name.split(".")[0].rstrip().upper() in reserved
        or any(
            ord(character) < 32
            or ord(character) == 127
            or character in '<>:"/\\|?*'
            for character in name
        )
    ):
        raise ValueError(
            "Недопустимое имя файла или папки."
        )

    return name


def safe_path(path):
    if path in {"", "/"}:
        return "/"

    parts = path.strip("/").split("/")

    if len(path) > 1000 or len(parts) > 12:
        raise ValueError(
            "Слишком длинный путь."
        )

    return "/" + "/".join(
        safe_name(part)
        for part in parts
    )


def join_path(parent, name):
    return safe_path(
        safe_path(parent).rstrip("/")
        + "/"
        + safe_name(name)
    )


def certificate_files(directory):
    certificate_path = directory / "ftp-certificate.pem"
    key_path = directory / "ftp-key.pem"

    if certificate_path.exists() and key_path.exists():
        certificate = x509.load_pem_x509_certificate(
            certificate_path.read_bytes()
        )

        if certificate.not_valid_after_utc > (
            datetime.now(timezone.utc)
            + timedelta(days=1)
        ):
            return certificate_path, key_path

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    name = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "Moe Oblako Local",
            )
        ]
    )

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(
                        ipaddress.ip_address("127.0.0.1")
                    ),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=0,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    key_path.chmod(0o600)

    certificate_path.write_bytes(
        certificate.public_bytes(
            serialization.Encoding.PEM
        )
    )

    return certificate_path, key_path


class Authorizer(DummyAuthorizer):
    def __init__(self, storage):
        super().__init__()
        self.storage = storage

    def account(self, username):
        if (
            username.isascii()
            and username.isdigit()
            and len(username) < 11
        ):
            return self.storage.database.get(
                int(username)
            )

        return None

    def has_user(self, username):
        user = self.account(username)

        return bool(
            user and user["active"]
        )

    def validate_authentication(
        self,
        username,
        password,
        handler,
    ):
        user = self.account(username)

        if (
            not user
            or not user["active"]
            or not hmac.compare_digest(
                password.encode("utf-8"),
                self.storage.token(user).encode("ascii"),
            )
        ):
            raise AuthenticationFailed(
                "Authentication failed."
            )

    def get_home_dir(self, username):
        return str(
            self.storage.home(int(username))
        )

    def get_perms(self, username):
        return "elrdfmw"

    def has_perm(self, username, perm, path=None):
        return (
            self.has_user(username)
            and perm in self.get_perms(username)
        )

    def get_msg_login(self, username):
        return "Private storage ready."

    def get_msg_quit(self, username):
        return "Goodbye."


class Storage:
    def __init__(self, directory, database):
        self.database = database
        self.root = directory / "files"
        self.root.mkdir(exist_ok=True)

        self.secret = secrets.token_bytes(32)
        self.guard = threading.Lock()
        self.locks = {}

        self.certificate, key = certificate_files(
            directory
        )

        context = SSL.Context(
            SSL.TLS_SERVER_METHOD
        )

        context.set_min_proto_version(
            SSL.TLS1_2_VERSION
        )

        context.use_certificate_chain_file(
            str(self.certificate)
        )

        context.use_privatekey_file(
            str(key)
        )

        class Handler(TLS_FTPHandler):
            pass

        Handler.authorizer = Authorizer(self)
        Handler.ssl_context = context
        Handler.tls_control_required = True
        Handler.tls_data_required = True
        Handler.permit_foreign_addresses = False
        Handler.timeout = 30
        Handler.auth_failed_timeout = 0.1

        self.server = FTPServer(
            ("127.0.0.1", 0),
            Handler,
            ioloop=IOLoop(),
        )

        self.server.max_cons = 32
        self.server.max_cons_per_ip = 32

        self.port = (
            self.server.socket.getsockname()[1]
        )

        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={
                "timeout": 0.1,
                "handle_exit": False,
            },
            daemon=True,
        )

        self.thread.start()

    def home(self, user_id):
        home = self.root / str(user_id)
        home.mkdir(exist_ok=True)

        if (
            home.is_symlink()
            or home.resolve().parent != self.root
        ):
            raise ValueError(
                "Недопустимая папка пользователя."
            )

        return home

    def token(self, user):
        message = (
            f"{user['id']}:{user['version']}"
        ).encode("ascii")

        return hmac.new(
            self.secret,
            message,
            hashlib.sha256,
        ).hexdigest()

    def lock(self, user_id):
        with self.guard:
            return self.locks.setdefault(
                user_id,
                threading.RLock(),
            )

    def usage(self, user):
        size = 0
        count = 0

        for entry in self.home(user["id"]).rglob("*"):
            if entry.is_symlink():
                raise ValueError(
                    "Символические ссылки запрещены."
                )

            count += 1

            if entry.is_file():
                size += entry.stat().st_size

        return size, count

    @contextmanager
    def connect(self, user):
        context = ssl.create_default_context(
            cafile=str(self.certificate)
        )

        context.minimum_version = (
            ssl.TLSVersion.TLSv1_2
        )

        client = FTP_TLS(
            context=context,
            timeout=20,
            encoding="utf-8",
        )

        try:
            client.connect(
                "127.0.0.1",
                self.port,
            )

            client.login(
                str(user["id"]),
                self.token(user),
            )

            client.prot_p()

            yield client

        finally:
            client.close()

    def close(self):
        if self.server is not None:
            self.server.close_all()
            self.thread.join(timeout=3)
            self.server = None