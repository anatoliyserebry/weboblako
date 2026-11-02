import io
import logging
import os
import re
import tempfile
import unittest
from unittest.mock import patch

from app import create_app
from database import Database

logging.getLogger("pyftpdlib").setLevel(logging.WARNING)


class FileFeaturesTests(unittest.TestCase):
    def setUp(self):
        logging.getLogger("pyftpdlib").setLevel(logging.WARNING)
        self.directory = tempfile.TemporaryDirectory(prefix="weboblako-test-")
        self.app = create_app(self.directory.name)
        self.app.config["TESTING"] = True
        self.database = self.app.extensions["database"]
        self.records = self.app.extensions["records"]
        self.storage = self.app.extensions["storage"]
        self.alice = self.database.create("alice", "test-password-alice", first=True)
        self.bob = self.database.create("bob", "test-password-bob")
        self.owner = self.app.test_client()
        self.visitor = self.app.test_client()
        self.sign_in(self.owner, self.alice)
        self.sign_in(self.visitor, self.bob)

    def tearDown(self):
        self.app.extensions["storage"].close()
        self.directory.cleanup()

    @staticmethod
    def sign_in(client, user):
        with client.session_transaction() as session:
            session.update(user_id=user["id"], version=user["version"], csrf="test-csrf")

    def post(self, url, client=None, **data):
        client = client or self.owner
        with client.session_transaction() as session:
            csrf = session.setdefault("csrf", "test-csrf")
        return client.post(url, data={"csrf": csrf, **data})

    def folder(self, path="/", name="Public"):
        self.assertEqual(self.post("/folder", path=path, name=name).status_code, 302)

    def upload(self, name="notes.txt", content=b"hello", path="/", client=None):
        response = self.post("/upload", client=client, path=path,
                             file=(io.BytesIO(content), name))
        self.assertEqual(response.status_code, 302, response.text)

    def download(self, url, client=None):
        with (client or self.owner).get(url) as response:
            return response.data

    def share(self, path="/Public"):
        self.assertEqual(self.post("/share", path=path).status_code, 302)
        return next(item["token"] for item in self.records.own_shares(self.alice["id"])
                    if item["path"].casefold() == path.casefold())

    def trash_item(self, path):
        return next(item for item in self.records.trash_items(self.alice["id"])
                    if item["original_path"] == path)

    def test_private_files_trash_and_history_are_isolated(self):
        self.upload("private.txt", b"private content")
        self.assertNotIn("private.txt", self.visitor.get("/").text)
        self.assertNotEqual(self.visitor.get("/download?path=/private.txt").status_code, 200)
        self.assertEqual(self.post("/delete", client=self.visitor, path="/private.txt",
                                   owner_id=self.alice["id"]).status_code, 404)
        self.assertEqual(self.post("/delete", path="/private.txt").status_code, 302)
        item = self.trash_item("/private.txt")
        self.assertNotIn("private.txt", self.visitor.get("/?tab=trash").text)
        self.assertNotIn("private.txt", self.visitor.get("/?tab=history").text)
        for action in ("restore", "purge"):
            self.assertEqual(self.post(f"/trash/{item['id']}/{action}",
                                       client=self.visitor).status_code, 404)

    def test_delete_and_restore_preserve_file_bytes(self):
        content = b"\x00original bytes\xff"
        self.upload(content=content)
        before = self.storage.usage(self.alice)[0]
        self.assertEqual(self.post("/delete", path="/notes.txt").status_code, 302)
        item = self.trash_item("/notes.txt")
        self.assertEqual(self.storage.usage(self.alice)[0], before)
        self.assertNotIn('data-name="notes.txt"', self.owner.get("/").text)
        self.assertEqual(self.post(f"/trash/{item['id']}/restore").status_code, 302)
        self.assertEqual(self.download("/download?path=/notes.txt"), content)
        self.assertEqual(self.records.trash_items(self.alice["id"]), [])
        actions = [event["action"] for event in self.records.history(self.alice["id"])]
        self.assertEqual(actions, ["restore", "delete", "upload"])

    def test_restore_does_not_overwrite_existing_file(self):
        self.upload(content=b"old")
        self.post("/delete", path="/notes.txt")
        item = self.trash_item("/notes.txt")
        self.upload(content=b"new")
        self.assertEqual(self.post(f"/trash/{item['id']}/restore").status_code, 400)
        self.assertEqual(self.download("/download?path=/notes.txt"), b"new")
        self.assertIsNotNone(self.records.trash_item(self.alice["id"], item["id"]))

    def test_restore_waits_for_missing_parent(self):
        self.folder()
        self.upload(path="/Public")
        self.post("/delete", path="/Public/notes.txt")
        file_item = self.trash_item("/Public/notes.txt")
        self.post("/delete", path="/Public")
        folder_item = self.trash_item("/Public")
        self.assertEqual(self.post(f"/trash/{file_item['id']}/restore").status_code, 400)
        self.assertEqual(self.post(f"/trash/{folder_item['id']}/restore").status_code, 302)
        self.assertEqual(self.post(f"/trash/{file_item['id']}/restore").status_code, 302)
        self.assertEqual(self.download("/download?path=/Public/notes.txt"), b"hello")

    def test_folder_with_children_is_recoverable_and_purge_is_recursive(self):
        self.folder()
        self.folder("/Public", "Nested")
        self.upload(path="/Public/Nested")
        self.upload("keep.txt", b"keep")
        self.post("/delete", path="/Public")
        item = self.trash_item("/Public")
        self.assertEqual(self.post(f"/trash/{item['id']}/restore").status_code, 302)
        self.assertEqual(self.download("/download?path=/Public/Nested/notes.txt"), b"hello")
        self.post("/delete", path="/Public")
        item = self.trash_item("/Public")
        self.assertEqual(self.post(f"/trash/{item['id']}/purge").status_code, 302)
        self.assertFalse((self.storage.home(self.alice["id"]) / ".trash" / item["id"]).exists())
        self.assertEqual(self.download("/download?path=/keep.txt"), b"keep")
        self.assertEqual(self.records.trash_items(self.alice["id"]), [])

    def test_trash_still_counts_towards_quota(self):
        with patch("app.QUOTA", 5):
            self.upload(content=b"1234")
            self.post("/delete", path="/notes.txt")
            response = self.post("/upload", path="/", file=(io.BytesIO(b"12"), "extra.txt"))
            self.assertEqual(response.status_code, 400)

    def test_purge_handles_interrupted_upload_inside_folder(self):
        self.folder()
        hidden = self.storage.home(self.alice["id"]) / "Public" / ".upload-test"
        hidden.write_bytes(b"interrupted upload")
        self.assertEqual(self.post("/delete", path="/Public").status_code, 302)
        item = self.trash_item("/Public")
        self.assertEqual(self.post(f"/trash/{item['id']}/purge").status_code, 302)
        self.assertEqual(self.records.trash_items(self.alice["id"]), [])

    def test_shared_folder_requires_login_and_returns_after_sign_in(self):
        self.folder()
        self.upload(path="/Public")
        token = self.share()
        anonymous = self.app.test_client()
        response = anonymous.get(f"/s/{token}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('name="next"', response.text)
        response = self.post("/account/login", client=anonymous, username="bob",
                             password="test-password-bob", next=f"/s/{token}")
        self.assertEqual(response.location, f"/s/{token}")
        self.assertIn("notes.txt", anonymous.get(response.location).text)

    def test_shared_read_access_cannot_escape_or_modify_owner(self):
        self.folder()
        self.folder("/Public", "Nested")
        self.upload(path="/Public/Nested")
        self.upload("private.txt", b"secret")
        token = self.share()
        root = f"/s/{token}"
        self.assertEqual(self.visitor.get(root + "?path=/Nested").status_code, 200)
        self.assertEqual(self.download(root + "/download?path=/Nested/notes.txt", self.visitor), b"hello")
        self.assertNotIn("/upload", self.visitor.get(root).text)
        for path in ("/../private.txt", "/.trash/item", "/private.txt"):
            self.assertNotEqual(self.visitor.get(root + "/download", query_string={"path": path}).status_code, 200)
        self.assertEqual(self.post(root, client=self.visitor, path="/Nested/notes.txt").status_code, 405)
        self.assertEqual(self.post(f"/share/{token}/revoke", client=self.visitor).status_code, 400)
        self.assertEqual(self.download("/download?path=/private.txt"), b"secret")
        self.assertIsNotNone(self.records.share(token))

    def test_shared_visits_and_owner_revoke(self):
        self.folder()
        token = self.share()
        self.visitor.get(f"/s/{token}")
        self.assertIn("Public", self.visitor.get("/?tab=shared").text)
        self.assertEqual(self.post(f"/share/{token}/revoke").status_code, 302)
        self.assertEqual(self.visitor.get(f"/s/{token}").status_code, 404)
        self.assertEqual(self.records.received_shares(self.bob["id"]), [])

    def test_deleted_folder_links_stay_revoked_after_restore(self):
        self.folder()
        self.folder("/Public", "Nested")
        token = self.share()
        nested_token = self.share("/Public/Nested")
        self.post("/delete", path="/Public")
        item = self.trash_item("/Public")
        self.post(f"/trash/{item['id']}/restore")
        for old_token in (token, nested_token):
            self.assertEqual(self.visitor.get(f"/s/{old_token}").status_code, 404)
        new_token = self.share()
        self.assertNotEqual(new_token, token)
        self.assertEqual(self.visitor.get(f"/s/{new_token}").status_code, 200)

    def test_rename_updates_nested_links_and_trash_restore_paths(self):
        self.folder()
        self.folder("/Public", "Nested")
        self.upload(path="/Public/Nested")
        token = self.share("/Public/Nested")
        self.post("/delete", path="/Public/Nested/notes.txt")
        item = self.trash_item("/Public/Nested/notes.txt")
        self.assertEqual(self.post("/rename", path="/Public", name="Renamed").status_code, 302)
        self.assertEqual(self.records.share(token)["path"], "/Renamed/Nested")
        self.assertEqual(self.post(f"/trash/{item['id']}/restore").status_code, 302)
        self.assertEqual(self.download(f"/s/{token}/download?path=/notes.txt", self.visitor), b"hello")
        event = next(event for event in self.records.history(self.alice["id"])
                     if event["action"] == "rename")
        self.assertEqual((event["actor"], event["path"], event["new_path"]),
                         ("alice", "/Public", "/Renamed"))

    def test_rename_collision_and_root_operations_are_rejected(self):
        self.upload("first.txt", b"first")
        self.upload("second.txt", b"second")
        self.assertEqual(self.post("/rename", path="/first.txt", name="second.txt").status_code, 400)
        for url, data in (("/delete", {}), ("/share", {}), ("/rename", {"name": "root"})):
            self.assertEqual(self.post(url, path="/", **data).status_code, 400)
        self.assertEqual(self.download("/download?path=/first.txt"), b"first")

    def test_sorting_by_type_and_size_keeps_folders_first(self):
        self.folder(name="Zfolder")
        for name, content in (("b.txt", b"12345"), ("a.jpg", b"123"),
                              ("z.pdf", b"12345678"), ("no_extension", b"1")):
            self.upload(name, content)
        def names(sort):
            return re.findall(r'data-name="([^"]+)"', self.owner.get("/", query_string={"sort": sort}).text)
        self.assertEqual(names("type"), ["Zfolder", "no_extension", "a.jpg", "z.pdf", "b.txt"])
        self.assertEqual(names("size"), ["Zfolder", "no_extension", "a.jpg", "b.txt", "z.pdf"])
        self.assertEqual(names("unknown"), names("name"))

    def test_history_pagination_and_scope(self):
        for number in range(55):
            self.records.log(self.alice, "upload", f"/file-{number}.txt")
        self.records.log(self.bob, "upload", "/bob-private.txt")
        first = self.owner.get("/?tab=history").text
        second = self.owner.get("/?tab=history&page=2").text
        self.assertEqual(first.count("Добавил файл"), 50)
        self.assertEqual(second.count("Добавил файл"), 5)
        self.assertNotIn("bob-private.txt", first + second)
        self.assertEqual(self.owner.get("/?tab=history&page=" + "9" * 100).status_code, 200)

    def test_failed_metadata_transaction_rolls_back_trash_and_revocation(self):
        self.folder()
        self.upload(path="/Public")
        token = self.share()
        with patch.object(self.records, "_log", side_effect=RuntimeError("test database failure")), self.assertLogs(level="ERROR"):
            self.assertEqual(self.post("/delete", path="/Public").status_code, 500)
        self.assertEqual(self.download("/download?path=/Public/notes.txt"), b"hello")
        self.assertEqual(self.records.trash_items(self.alice["id"]), [])
        self.assertIsNotNone(self.records.share(token))

    def test_repeated_share_creation_reuses_link(self):
        self.folder()
        first = self.share()
        self.assertEqual(self.share(), first)
        self.assertEqual(len(self.records.own_shares(self.alice["id"])), 1)

    def test_renaming_new_file_does_not_move_old_deleted_file(self):
        self.upload(content=b"old")
        self.post("/delete", path="/notes.txt")
        item = self.trash_item("/notes.txt")
        self.upload(content=b"new")
        self.post("/rename", path="/notes.txt", name="new.txt")
        self.assertEqual(self.post(f"/trash/{item['id']}/restore").status_code, 302)
        self.assertEqual(self.download("/download?path=/notes.txt"), b"old")
        self.assertEqual(self.download("/download?path=/new.txt"), b"new")

    @unittest.skipUnless(os.name == "nt", "Windows filesystem case aliases")
    def test_case_aliases_cannot_keep_deleted_folder_links_active(self):
        self.folder()
        self.folder("/Public", "Nested")
        token = self.share("/Public/Nested")
        self.assertEqual(self.share("/PUBLIC/Nested"), token)
        self.assertEqual(self.post("/delete", path="/PUBLIC/Nested").status_code, 302)
        self.assertIsNone(self.records.share(token))

    def test_records_links_and_files_survive_restart(self):
        self.folder()
        token = self.share()
        self.upload()
        self.post("/delete", path="/notes.txt")
        item = self.trash_item("/notes.txt")
        self.storage.close()
        self.app = create_app(self.directory.name)
        self.owner = self.app.test_client()
        self.sign_in(self.owner, self.alice)
        self.assertEqual(len(self.app.extensions["database"].users()), 2)
        self.assertEqual(self.owner.get(f"/s/{token}").status_code, 200)
        self.assertEqual(self.post(f"/trash/{item['id']}/restore").status_code, 302)
        self.assertEqual(self.download("/download?path=/notes.txt"), b"hello")

    def test_csrf_and_authentication_protect_mutations(self):
        self.folder()
        for url in ("/delete", "/rename", "/share", "/trash/missing/restore", "/trash/missing/purge"):
            self.assertEqual(self.owner.post(url, data={"path": "/Public"}).status_code, 403)
        anonymous = self.app.test_client()
        anonymous.get("/")
        self.assertEqual(self.post("/share", client=anonymous, path="/Public").status_code, 401)

    def test_login_next_cannot_redirect_to_external_site(self):
        client = self.app.test_client()
        client.get("/")
        for target in ("https://example.com/", "//example.com/s/test", "http://[bad"):
            response = self.post("/account/login", client=client, username="bob",
                                 password="test-password-bob", next=target)
            self.assertEqual(response.location, "/")


class ExistingDataTests(unittest.TestCase):
    def test_users_only_database_is_migrated_without_losing_files(self):
        with tempfile.TemporaryDirectory(prefix="weboblako-migration-") as directory:
            from pathlib import Path
            root = Path(directory)
            database = Database(root / "accounts.sqlite3")
            user = database.create("existing_user", "existing-password", first=True)
            home = root / "files" / str(user["id"])
            home.mkdir(parents=True)
            (home / "existing.txt").write_bytes(b"existing file")
            app = create_app(directory)
            try:
                client = app.test_client()
                FileFeaturesTests.sign_in(client, user)
                with client.get("/download?path=/existing.txt") as response:
                    self.assertEqual(response.data, b"existing file")
                self.assertIsNotNone(app.extensions["database"].authenticate("existing_user", "existing-password"))
                self.assertEqual(client.get("/?tab=trash").status_code, 200)
                self.assertEqual(client.get("/?tab=history").status_code, 200)
            finally:
                app.extensions["storage"].close()


if __name__ == "__main__":
    unittest.main()
