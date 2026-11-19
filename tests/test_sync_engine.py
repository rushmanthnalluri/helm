"""tests/test_sync_engine.py - Acceptance Tests for Helm Priority 4 Cross-Device Sync.

Covers:
1. End-to-end local encryption (AES-256-GCM + PBKDF2) and tampering resistance.
2. Conflict resolution (Timestamped LWW + UUID deduplication + deterministic tie-break).
3. Offline queue behavior and offline-first persistence.
4. Local bundle backup (.helmbundle.json) export and import (both encrypted and plaintext).
5. Provider-agnostic adapters (Supabase, Firebase, Generic Webhook, FileBundle, MockSync).
6. Multi-device bidirectional sync simulation.
7. Durable memory store (durable_memory.py) integration and automatic mutation callbacks.
8. Sync status API inspection.
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import durable_memory
from durable_memory import DurableMemoryStore
import helm_sync
from helm_sync import (
    CryptoError,
    FileBundleAdapter,
    HelmSyncManager,
    MockSyncAdapter,
    RestSyncAdapter,
    SyncCrypto,
    SyncRecord,
    resolve_record_conflict,
)


class TestSyncCrypto(unittest.TestCase):
    """Verifies AES-256-GCM + PBKDF2 authenticated encryption."""

    def test_encryption_and_decryption_roundtrip(self):
        passphrase = "correct_horse_battery_staple"
        data = {
            "facts": {"user_name": "Rush", "theme": "cyberpunk"},
            "count": 42,
            "nested": {"active": True},
        }

        # Encrypt with standard 100k iterations (using 10k here for high-speed test execution)
        envelope = SyncCrypto.encrypt_payload(data, passphrase, iterations=10_000)
        self.assertTrue(envelope["encrypted"])
        self.assertEqual(envelope["algorithm"], "AES-256-GCM")
        self.assertEqual(envelope["kdf"], "PBKDF2-HMAC-SHA256")
        self.assertIn("ciphertext", envelope)
        self.assertIn("nonce", envelope)
        self.assertIn("salt", envelope)

        # Decrypt
        decrypted = SyncCrypto.decrypt_payload(envelope, passphrase)
        self.assertEqual(decrypted, data)

    def test_decryption_fails_with_wrong_passphrase(self):
        data = {"secret_fact": "classified"}
        envelope = SyncCrypto.encrypt_payload(data, "right_password", iterations=10_000)

        with self.assertRaises(ValueError) as ctx:
            SyncCrypto.decrypt_payload(envelope, "wrong_password")
        self.assertIn("decryption failed", str(ctx.exception).lower())

    def test_decryption_fails_on_tampered_ciphertext(self):
        import base64
        data = {"secret_fact": "classified"}
        envelope = SyncCrypto.encrypt_payload(data, "password123", iterations=10_000)

        # Tamper with the raw ciphertext
        raw_ct = bytearray(base64.b64decode(envelope["ciphertext"]))
        raw_ct[0] ^= 0xFF  # Flip bits
        envelope["ciphertext"] = base64.b64encode(bytes(raw_ct)).decode("ascii")

        with self.assertRaises(ValueError) as ctx:
            SyncCrypto.decrypt_payload(envelope, "password123")
        self.assertIn("decryption failed", str(ctx.exception).lower())

    def test_empty_passphrase_rejected(self):
        with self.assertRaises(CryptoError):
            SyncCrypto.encrypt_payload({"a": 1}, "")


class TestConflictResolution(unittest.TestCase):
    """Verifies Timestamped Last-Write-Wins and UUID deduplication."""

    def test_uuid_deduplication(self):
        rec_id = "rec-uuid-1234"
        local = SyncRecord(id=rec_id, key="name", value="Rush", updated_at=100.0)
        incoming = SyncRecord(id=rec_id, key="name", value="Rush", updated_at=100.0)

        winner, changed = resolve_record_conflict(local, incoming)
        self.assertFalse(changed)
        self.assertEqual(winner.id, rec_id)

    def test_lww_newer_timestamp_wins(self):
        local = SyncRecord(id="uuid-1", key="city", value="New York", updated_at=100.0)
        incoming = SyncRecord(id="uuid-2", key="city", value="San Francisco", updated_at=150.0)

        # Incoming is newer -> incoming wins
        winner, changed = resolve_record_conflict(local, incoming)
        self.assertTrue(changed)
        self.assertEqual(winner.value, "San Francisco")
        self.assertEqual(winner.id, "uuid-2")

        # Reverse order: incoming is older -> local wins
        older_incoming = SyncRecord(id="uuid-3", key="city", value="Chicago", updated_at=80.0)
        winner2, changed2 = resolve_record_conflict(local, older_incoming)
        self.assertFalse(changed2)
        self.assertEqual(winner2.value, "New York")
        self.assertEqual(winner2.id, "uuid-1")

    def test_equal_timestamp_deterministic_tiebreak(self):
        # When updated_at is identical, tie-breaker must produce identical result regardless of eval order
        rec_a = SyncRecord(id="uuid-a", device_id="dev-a", key="pref", value="val-a", updated_at=100.0)
        rec_b = SyncRecord(id="uuid-b", device_id="dev-b", key="pref", value="val-b", updated_at=100.0)

        winner1, changed1 = resolve_record_conflict(rec_a, rec_b)
        winner2, changed2 = resolve_record_conflict(rec_b, rec_a)

        # "dev-b" > "dev-a" -> rec_b wins in both evaluations
        self.assertEqual(winner1.id, rec_b.id)
        self.assertEqual(winner2.id, rec_b.id)

    def test_deletion_tombstone_resolution(self):
        # A newer deletion tombstone overrides older fact
        local = SyncRecord(id="uuid-1", key="coffee", value="espresso", updated_at=100.0, deleted=False)
        tombstone = SyncRecord(id="uuid-2", key="coffee", value="", updated_at=150.0, deleted=True)

        winner, changed = resolve_record_conflict(local, tombstone)
        self.assertTrue(changed)
        self.assertTrue(winner.deleted)

        # A newer update overrides older tombstone
        newer_fact = SyncRecord(id="uuid-3", key="coffee", value="cold brew", updated_at=200.0, deleted=False)
        winner2, changed2 = resolve_record_conflict(winner, newer_fact)
        self.assertTrue(changed2)
        self.assertFalse(winner2.deleted)
        self.assertEqual(winner2.value, "cold brew")


class TestOfflineQueueAndEngine(unittest.TestCase):
    """Verifies offline queue, graceful offline behavior, and sync state transitions."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.mock_adapter = MockSyncAdapter()
        self.manager = HelmSyncManager(
            data_dir=self.data_dir,
            passphrase="master-sync-key",
            adapter=self.mock_adapter,
        )

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_offline_queue_stages_changes(self):
        # Create facts, preferences, settings while offline
        self.manager.set_fact("user_name", "Rush")
        self.manager.set_preference("theme", "cyberpunk")
        self.manager.set_setting("hotkey", "Alt+Space")

        status = self.manager.get_sync_status()
        self.assertEqual(status["pending_changes_count"], 3)
        self.assertEqual(len(self.manager.offline_queue), 3)

        # Re-initialize manager from same data_dir to verify disk persistence of queue
        restarted = HelmSyncManager(
            data_dir=self.data_dir,
            passphrase="master-sync-key",
            adapter=self.mock_adapter,
        )
        self.assertEqual(len(restarted.offline_queue), 3)
        self.assertEqual(restarted.get_fact("user_name"), "Rush")
        self.assertEqual(restarted.get_preference("theme"), "cyberpunk")
        self.assertEqual(restarted.get_setting("hotkey"), "Alt+Space")

    def test_trigger_sync_fails_gracefully_when_adapter_offline(self):
        self.manager.set_fact("favorite_editor", "Antigravity")
        self.mock_adapter.online = False

        ok, msg = self.manager.trigger_sync()
        self.assertFalse(ok)
        self.assertIn("offline", msg.lower())

        status = self.manager.get_sync_status()
        self.assertEqual(status["status"], "offline")
        # Queued changes are preserved!
        self.assertEqual(status["pending_changes_count"], 1)

    def test_trigger_sync_flushes_queue_when_online(self):
        self.manager.set_fact("favorite_food", "Pizza")
        self.assertEqual(len(self.manager.offline_queue), 1)

        self.mock_adapter.online = True
        ok, msg = self.manager.trigger_sync()
        self.assertTrue(ok, msg)

        status = self.manager.get_sync_status()
        self.assertEqual(status["status"], "synced")
        self.assertEqual(status["pending_changes_count"], 0)
        self.assertIsNotNone(status["last_sync_time"])
        self.assertEqual(len(self.manager.offline_queue), 0)

        # Remote storage should now contain encrypted payload, NOT plaintext!
        remote_data = self.mock_adapter.storage
        self.assertIsNotNone(remote_data)
        self.assertTrue(remote_data.get("encrypted"))
        self.assertIn("ciphertext", remote_data)
        self.assertNotIn("Pizza", str(remote_data))


class TestBackupBundleImportExport(unittest.TestCase):
    """Verifies .helmbundle.json export and import."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.manager = HelmSyncManager(data_dir=self.data_dir, passphrase="bundle-passphrase")

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_export_and_import_encrypted_bundle(self):
        self.manager.set_fact("role", "Architect")
        self.manager.set_preference("font_size", 14)
        self.manager.set_setting("auto_save", True)

        bundle_path = self.manager.export_backup()
        self.assertTrue(os.path.exists(bundle_path))
        self.assertTrue(bundle_path.endswith(".helmbundle.json"))

        # Verify bundle content is encrypted
        content = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
        self.assertEqual(content["format"], "helm_bundle")
        self.assertTrue(content["encrypted"])
        self.assertNotIn("Architect", str(content))

        # Import into fresh clean manager
        fresh_dir = self.data_dir / "fresh_client"
        fresh_manager = HelmSyncManager(data_dir=fresh_dir, passphrase="bundle-passphrase")
        summary = fresh_manager.import_backup(bundle_path)

        self.assertEqual(summary["facts_restored"], 1)
        self.assertEqual(summary["preferences_restored"], 1)
        self.assertEqual(summary["settings_restored"], 1)
        self.assertEqual(fresh_manager.get_fact("role"), "Architect")
        self.assertEqual(fresh_manager.get_preference("font_size"), 14)
        self.assertEqual(fresh_manager.get_setting("auto_save"), True)

    def test_import_with_wrong_passphrase_fails(self):
        self.manager.set_fact("secret_note", "12345")
        bundle_path = self.manager.export_backup(passphrase="correct-key")

        fresh_dir = self.data_dir / "wrong_key_client"
        fresh_manager = HelmSyncManager(data_dir=fresh_dir)

        with self.assertRaises(ValueError) as ctx:
            fresh_manager.import_backup(bundle_path, passphrase="wrong-key")
        self.assertIn("decryption failed", str(ctx.exception).lower())

    def test_export_and_import_unencrypted_bundle(self):
        unencrypted_manager = HelmSyncManager(data_dir=self.data_dir / "unencrypted")
        unencrypted_manager.set_fact("open_fact", "Public knowledge")

        bundle_path = unencrypted_manager.export_backup()
        content = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
        self.assertFalse(content["encrypted"])

        fresh_manager = HelmSyncManager(data_dir=self.data_dir / "unencrypted_fresh")
        summary = fresh_manager.import_backup(bundle_path)
        self.assertEqual(summary["facts_restored"], 1)
        self.assertEqual(fresh_manager.get_fact("open_fact"), "Public knowledge")


class TestProviderAdapters(unittest.TestCase):
    """Verifies provider adapters for Supabase, Firebase, and generic REST."""

    def test_file_bundle_adapter(self):
        with tempfile.TemporaryDirectory() as td:
            bundle_file = Path(td) / "sync_folder" / "shared.helmbundle.json"
            adapter = FileBundleAdapter(bundle_file)
            self.assertTrue(adapter.is_available())

            # Initially empty
            self.assertIsNone(adapter.pull())

            payload = {"version": 1, "data": "test_data"}
            ok = adapter.push(payload)
            self.assertTrue(ok)
            self.assertTrue(bundle_file.exists())

            pulled = adapter.pull()
            self.assertEqual(pulled, payload)

    def test_supabase_rest_adapter_headers_and_payload(self):
        recorded_requests = []

        def mock_http_handler(req: urllib.request.Request):
            recorded_requests.append(req)
            if req.get_method() == "GET":
                # Supabase returns JSON list of rows
                response_data = [{"sync_id": "test_sync", "payload": {"status": "ok"}}]
                return 200, json.dumps(response_data).encode("utf-8")
            elif req.get_method() == "POST":
                return 201, b""
            return 400, b""

        adapter = RestSyncAdapter(
            endpoint="https://xyz.supabase.co/rest/v1/helm_sync",
            provider="supabase",
            api_key="anon-key-123",
            auth_token="user-jwt-456",
            sync_id="tenant-1",
            request_handler=mock_http_handler,
        )

        pulled = adapter.pull()
        self.assertEqual(pulled, {"status": "ok"})
        self.assertEqual(len(recorded_requests), 1)
        get_req = recorded_requests[0]
        self.assertEqual(get_req.get_header("Apikey"), "anon-key-123")
        self.assertEqual(get_req.get_header("Authorization"), "Bearer user-jwt-456")
        self.assertIn("sync_id=eq.tenant-1", get_req.full_url)

        push_ok = adapter.push({"encrypted": True})
        self.assertTrue(push_ok)
        post_req = recorded_requests[1]
        self.assertEqual(post_req.get_method(), "POST")
        self.assertEqual(post_req.get_header("Prefer"), "resolution=merge-duplicates,return=minimal")
        posted_body = json.loads(post_req.data.decode("utf-8"))
        self.assertEqual(posted_body["sync_id"], "tenant-1")
        self.assertEqual(posted_body["payload"], {"encrypted": True})

    def test_firebase_rest_adapter_url_and_methods(self):
        recorded_requests = []

        def mock_firebase_handler(req: urllib.request.Request):
            recorded_requests.append(req)
            if req.get_method() == "GET":
                return 200, json.dumps({"encrypted_data": "firebase_payload"}).encode("utf-8")
            elif req.get_method() == "PUT":
                return 200, b"{}"
            return 400, b""

        adapter = RestSyncAdapter(
            endpoint="https://test-project.firebaseio.com",
            provider="firebase",
            auth_token="fb-token-999",
            sync_id="user_primary",
            request_handler=mock_firebase_handler,
        )

        pulled = adapter.pull()
        self.assertEqual(pulled, {"encrypted_data": "firebase_payload"})
        get_req = recorded_requests[0]
        self.assertIn("/helm_sync/user_primary.json?auth=fb-token-999", get_req.full_url)

        push_ok = adapter.push({"data": 123})
        self.assertTrue(push_ok)
        put_req = recorded_requests[1]
        self.assertEqual(put_req.get_method(), "PUT")
        self.assertIn("/helm_sync/user_primary.json?auth=fb-token-999", put_req.full_url)


class TestCrossDeviceBidirectionalSync(unittest.TestCase):
    """Simulates real multi-device synchronization between Device A and Device B."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.shared_remote = MockSyncAdapter(name="shared-cloud")
        self.passphrase = "shared-vault-passphrase"

        self.dev_a_dir = Path(self.temp_dir.name) / "device_a"
        self.dev_b_dir = Path(self.temp_dir.name) / "device_b"

        self.dev_a = HelmSyncManager(
            data_dir=self.dev_a_dir,
            device_id="device-A",
            passphrase=self.passphrase,
            adapter=self.shared_remote,
        )
        self.dev_b = HelmSyncManager(
            data_dir=self.dev_b_dir,
            device_id="device-B",
            passphrase=self.passphrase,
            adapter=self.shared_remote,
        )

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_bidirectional_sync_roundtrip(self):
        # 1. Device A sets a fact
        self.dev_a.set_fact("user_name", "Rush")
        ok, msg = self.dev_a.trigger_sync()
        self.assertTrue(ok, msg)

        # 2. Device B syncs and receives the fact
        ok, msg = self.dev_b.trigger_sync()
        self.assertTrue(ok, msg)
        self.assertEqual(self.dev_b.get_fact("user_name"), "Rush")

        # 3. Device B sets a preference
        self.dev_b.set_preference("editor", "Antigravity")
        ok, msg = self.dev_b.trigger_sync()
        self.assertTrue(ok, msg)

        # 4. Device A syncs and receives the preference
        ok, msg = self.dev_a.trigger_sync()
        self.assertTrue(ok, msg)
        self.assertEqual(self.dev_a.get_preference("editor"), "Antigravity")
        self.assertEqual(self.dev_a.get_fact("user_name"), "Rush")

    def test_cross_device_conflict_lww(self):
        # Device A sets an initial fact
        self.dev_a.set_fact("status", "Available")
        self.dev_a.trigger_sync()

        self.dev_b.trigger_sync()
        self.assertEqual(self.dev_b.get_fact("status"), "Available")

        # Concurrent modification:
        # Device A updates at t = 100.0
        rec_a = SyncRecord(
            category="fact",
            key="status",
            value="Busy in Meeting",
            device_id="device-A",
            updated_at=100.0,
        )
        self.dev_a.facts["status"] = rec_a

        # Device B updates at t = 150.0 (newer)
        rec_b = SyncRecord(
            category="fact",
            key="status",
            value="Do Not Disturb",
            device_id="device-B",
            updated_at=150.0,
        )
        self.dev_b.facts["status"] = rec_b

        # Device A pushes first
        self.dev_a.trigger_sync()

        # Device B syncs: its local t=150.0 is newer than Device A's t=100.0, so Device B's value wins
        self.dev_b.trigger_sync()
        self.assertEqual(self.dev_b.get_fact("status"), "Do Not Disturb")

        # Device A syncs: pulls Device B's newer value
        self.dev_a.trigger_sync()
        self.assertEqual(self.dev_a.get_fact("status"), "Do Not Disturb")


class TestDurableMemoryIntegration(unittest.TestCase):
    """Verifies live hook integration between DurableMemoryStore and HelmSyncManager."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.facts_file = self.data_dir / "facts.json"

        # Taint tracker standalone mode
        import taint_tracker
        taint_tracker.clear_all_taints()
        taint_tracker.set_standalone_mode(True)

        self.memory_store = DurableMemoryStore(self.facts_file)
        self.mock_adapter = MockSyncAdapter()
        self.sync_manager = HelmSyncManager(
            data_dir=self.data_dir / "sync",
            passphrase="memory-test-key",
            adapter=self.mock_adapter,
            memory_store=self.memory_store,
        )

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_store_mutation_auto_enqueues_in_sync_manager(self):
        # 1. Setting a fact in memory store triggers sync listener
        ok, msg = self.memory_store.set_fact("morning_drink", "Black coffee")
        self.assertTrue(ok, msg)

        # Fact is immediately reflected in sync manager
        self.assertEqual(self.sync_manager.get_fact("morning_drink"), "Black coffee")
        self.assertEqual(len(self.sync_manager.offline_queue), 1)

        # 2. Deleting a fact in memory store triggers tombstone enqueue
        ok, msg = self.memory_store.delete_fact("morning_drink")
        self.assertTrue(ok, msg)
        self.assertIsNone(self.sync_manager.get_fact("morning_drink"))
        self.assertEqual(len(self.sync_manager.offline_queue), 1)
        peeked = self.sync_manager.offline_queue.peek()
        self.assertEqual(peeked[0]["action"], "delete")

    def test_incoming_sync_updates_memory_store_without_recursion(self):
        # Prepare remote payload with incoming fact
        incoming_record = SyncRecord(
            category="fact",
            key="remote_learned_fact",
            value="The user speaks English and Spanish.",
            device_id="other-machine",
            updated_at=time.time(),
        )
        package = {
            "version": "1.0.0",
            "device_id": "other-machine",
            "records": [incoming_record.to_dict()],
        }
        encrypted = SyncCrypto.encrypt_payload(package, "memory-test-key")
        self.mock_adapter.storage = encrypted

        # Trigger sync on local machine
        ok, msg = self.sync_manager.trigger_sync()
        self.assertTrue(ok, msg)

        # DurableMemoryStore now contains the synced fact!
        self.assertEqual(
            self.memory_store.get_fact("remote_learned_fact"),
            "The user speaks English and Spanish.",
        )
        # Durable facts.json file reflects it on disk
        disk_facts = self.memory_store.list_facts()
        self.assertIn("remote_learned_fact", disk_facts)

    def test_store_export_and_import_helpers(self):
        self.memory_store.set_fact("lang", "Python")
        exported = self.memory_store.export_facts()
        self.assertEqual(exported, {"lang": "Python"})

        imported_count = self.memory_store.import_facts({"framework": "PyTorch", "os": "Windows"}, merge=True)
        self.assertEqual(imported_count, 2)
        all_facts = self.memory_store.list_facts()
        self.assertEqual(all_facts, {"lang": "Python", "framework": "PyTorch", "os": "Windows"})


class TestSyncModuleLevelAPI(unittest.TestCase):
    """Verifies module-level public functions."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.mock_adapter = MockSyncAdapter()
        self.manager = HelmSyncManager(
            data_dir=self.temp_dir.name,
            passphrase="top-level-key",
            adapter=self.mock_adapter,
        )
        helm_sync.set_sync_manager(self.manager)

    def tearDown(self):
        helm_sync.set_sync_manager(None)
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_top_level_status_and_sync(self):
        status = helm_sync.get_sync_status()
        self.assertEqual(status["status"], "never_synced")
        self.assertTrue(status["remote_configured"])
        self.assertTrue(status["encryption_enabled"])

        self.manager.set_fact("sample", "value")
        ok, msg = helm_sync.trigger_sync()
        self.assertTrue(ok, msg)

        new_status = helm_sync.get_sync_status()
        self.assertEqual(new_status["status"], "synced")
        self.assertEqual(new_status["stats"]["facts_count"], 1)

    def test_top_level_export_and_import(self):
        self.manager.set_fact("key1", "val1")
        export_file = Path(self.temp_dir.name) / "bundle.helmbundle.json"

        path_result = helm_sync.export_backup(file_path=export_file)
        self.assertEqual(path_result, str(export_file.resolve()))

        # Reset manager facts
        self.manager.facts.clear()
        self.assertEqual(self.manager.list_facts(), {})

        summary = helm_sync.import_backup(file_path=export_file)
        self.assertEqual(summary["facts_restored"], 1)
        self.assertEqual(self.manager.get_fact("key1"), "val1")

    def test_preferences_and_settings_crud_and_deletion(self):
        self.manager.set_preference("editor.font_family", "JetBrains Mono")
        self.assertEqual(self.manager.get_preference("editor.font_family"), "JetBrains Mono")
        self.assertIn("editor.font_family", self.manager.list_preferences())

        del_pref = self.manager.delete_preference("editor.font_family")
        self.assertTrue(del_pref)
        self.assertIsNone(self.manager.get_preference("editor.font_family"))

        self.manager.set_setting("sync.interval_seconds", 300)
        self.assertEqual(self.manager.get_setting("sync.interval_seconds"), 300)
        self.assertIn("sync.interval_seconds", self.manager.list_settings())

        del_setting = self.manager.delete_setting("sync.interval_seconds")
        self.assertTrue(del_setting)
        self.assertIsNone(self.manager.get_setting("sync.interval_seconds"))

    def test_generic_rest_adapter_get_and_post(self):
        requests_log = []

        def mock_generic_handler(req: urllib.request.Request):
            requests_log.append(req)
            if req.get_method() == "GET":
                return 200, json.dumps({"payload": {"test_field": "generic_val"}}).encode("utf-8")
            elif req.get_method() == "POST":
                return 201, b'{"status": "created"}'
            return 404, b""

        adapter = RestSyncAdapter(
            endpoint="https://api.mycustomservice.io/helm/sync",
            provider="generic",
            auth_token="jwt-token-xyz",
            sync_id="tenant-888",
            request_handler=mock_generic_handler,
        )

        self.assertTrue(adapter.is_available())
        ok, msg = adapter.test_connection()
        self.assertTrue(ok)

        pulled = adapter.pull()
        self.assertEqual(pulled, {"test_field": "generic_val"})
        self.assertEqual(requests_log[0].get_header("Authorization"), "Bearer jwt-token-xyz")
        self.assertIn("sync_id=tenant-888", requests_log[0].full_url)

        push_ok = adapter.push({"data": "sample"})
        self.assertTrue(push_ok)

    def test_rest_adapter_error_handling(self):
        def mock_failing_handler(req: urllib.request.Request):
            return 500, b"Internal Server Error"

        adapter = RestSyncAdapter(
            endpoint="https://api.failing.io",
            provider="generic",
            request_handler=mock_failing_handler,
        )
        with self.assertRaises(helm_sync.AdapterError):
            adapter.pull()

        with self.assertRaises(helm_sync.AdapterError):
            adapter.push({"key": "val"})

    def test_missing_adapter_and_passphrase_guards(self):
        bare_manager = HelmSyncManager(data_dir=Path(self.temp_dir.name) / "bare")
        # No adapter
        ok, msg = bare_manager.trigger_sync()
        self.assertFalse(ok)
        self.assertIn("no sync adapter", msg.lower())

        # Adapter set, but no passphrase
        bare_manager.set_adapter(self.mock_adapter)
        ok, msg = bare_manager.trigger_sync()
        self.assertFalse(ok)
        self.assertIn("passphrase is required", msg.lower())



if __name__ == "__main__":
    unittest.main()
