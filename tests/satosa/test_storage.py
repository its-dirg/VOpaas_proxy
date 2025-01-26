from unittest import TestCase
from unittest.mock import patch

from satosa.plugin_loader import load_storage
from satosa.storage import FrontendSession

CONFIG_INMEMORY = {"LOGOUT_ENABLED": True}
class TestInMemoryStorage(TestCase):
    def test_inmemory_store_frontend_session(self):
        config = CONFIG_INMEMORY
        storage = load_storage(config)
        storage.store_frontend_session(
            "OIDC", "requester-Azure", "sub-id", "sid-1FE"
        )
        assert storage.frontend_sessions

    def test_inmemory_get_frontend_session(self):
        config = CONFIG_INMEMORY
        storage = load_storage(config)
        assert not storage.get_frontend_session("sid-1FE")
        storage.store_frontend_session(
            "OIDC", "requester-Azure", "sub-id", "sid-1FE"
        )
        assert storage.get_frontend_session("sid-1FE")

    def test_inmemory_delete_frontend_session(self):
        config = CONFIG_INMEMORY
        storage = load_storage(config)
        storage.store_frontend_session(
            "OIDC", "requester-Azure", "sub-id", "sid-1FE"
        )
        storage.delete_frontend_session("sid-1FE")
        assert not storage.get_frontend_session("sid-1FE")

    def test_inmemory_store_backend_session(self):
        config = CONFIG_INMEMORY
        storage = load_storage(config)
        storage.store_backend_session("sid-1BE", "OIDC")
        assert storage.backend_sessions

    def test_inmemory_get_backend_session(self):
        config = CONFIG_INMEMORY
        storage = load_storage(config)
        storage.store_backend_session("sid-1BE", "OIDC")
        backend_session = storage.get_backend_session("sid-1BE", "OIDC")
        assert backend_session

    def test_inmemory_get_unique_backend_session_from_multiple_same_sid_backends(self):
        config = CONFIG_INMEMORY
        storage = load_storage(config)
        storage.store_backend_session("sid-1BE", "OIDC")
        storage.store_backend_session("sid-1BE", "OIDC2")
        backend_session = storage.get_backend_session("sid-1BE", "OIDC2")
        assert backend_session.get("issuer") == "OIDC2"

    def test_inmemory_get_backend_session_doesnot_exist(self):
        config = CONFIG_INMEMORY
        storage = load_storage(config)
        backend_session = storage.get_backend_session("sid-1BE", "OIDC2")
        assert not backend_session

    def test_inmemory_delete_backend_session(self):
        config = CONFIG_INMEMORY
        storage = load_storage(config)
        storage.store_backend_session("sid-1BE", "OIDC")
        storage.delete_backend_session(
            storage.get_backend_session("sid-1BE")["id"]
        )
        backend_session = storage.get_backend_session("sid-1BE")
        assert not backend_session

    def test_inmemory_store_session_map(self):
        config = CONFIG_INMEMORY
        storage = load_storage(config)
        storage.store_session_map("sid-1FE", "sid-1BE")
        assert storage.session_maps

    def test_inmemory_delete_session_map(self):
        config = CONFIG_INMEMORY
        storage = load_storage(config)
        storage.store_session_map("sid-1FE", "sid-1BE")
        storage.delete_session_map("sid-1FE")
        assert not storage.session_maps

    def test_inmemory_get_frontend_sessions_by_backend_session_id(self):
        config = CONFIG_INMEMORY
        storage = load_storage(config)
        assert not storage.get_frontend_sessions_by_backend_session_id(
            "sid-1BE"
        )
        storage.store_frontend_session(
            "OIDC", "requester-Azure", "sub-id", "sid-1FE"
        )
        storage.store_frontend_session(
            "OIDC", "requester-Azure", "sub-id", "sid-2FE"
        )
        storage.store_session_map("sid-1FE", "sid-1BE")
        storage.store_session_map("sid-2FE", "sid-1BE")
        backend_sessions = storage.get_frontend_sessions_by_backend_session_id(
            "sid-1BE"
        )
        assert len(backend_sessions) == 2


class TestPostgreSQLStorage(TestCase):
    @patch("sqlalchemy.orm.session.Session.query")
    @patch("sqlalchemy.orm.session.Session.commit")
    @patch("satosa.storage.Base")
    def test_postgresql_store_frontend_session(
        self, mock_base, mock_session_commit, mock_frontend_session_query
    ):
        config = {
            "LOGOUT_ENABLED": True,
            "STORAGE": {
                "type": "satosa.storage.StoragePostgreSQL",
                "host": "127.0.0.1",
                "port": 5432,
                "db_name": "satosa",
                "user": "postgres",
                "password": "secret",
            }
        }
        mock_base.return_value.metadata.return_value.create_all.return_value = None
        mock_session_commit.return_value = None
        storage = load_storage(config)
        storage.store_frontend_session(
            "OIDC", "requester-Azure", "sub-id", "sid-1FE"
        )

        frontend_session_mock = FrontendSession()
        frontend_session_mock.sid = "sid"
        frontend_session_mock.frontend_name = "frontend_name"
        frontend_session_mock.requester = "requester"
        frontend_session_mock.subject_id = "subject_id"
        mock_frontend_session_query.return_value.filter.return_value.first.return_value = (
            frontend_session_mock
        )

        frontend_session = storage.get_frontend_session("sid-1FE")
        assert frontend_session
