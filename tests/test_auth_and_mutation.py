import unittest
import os
from unittest.mock import MagicMock, patch
from core.auth import AuthManager

class TestAuthProtectedResource(unittest.TestCase):
    def _make_client(self, responses):
        client = MagicMock()
        client.request.side_effect = responses
        return client

    def test_login_fail_no_protected_resource(self):
        responses = []
        login_get = MagicMock()
        login_get.success = True
        login_get.response.text = '<input name="username"><input name="password">'
        login_get.response.status_code = 200
        login_get.response.url = "http://x/login.php"
        responses.append(login_get)
        login_post = MagicMock()
        login_post.success = True
        login_post.response.text = '<a href="/logout">Logout</a> Dashboard'
        login_post.response.status_code = 200
        login_post.response.url = "http://x/"
        responses.append(login_post)
        for path in ["/dashboard", "/profile", "/account", "/admin", "/user", "/settings"]:
            fail = MagicMock()
            fail.success = True
            fail.response.text = '<form><input name="password"></form>'
            fail.response.status_code = 200
            fail.response.url = "http://x/login.php"
            responses.append(fail)
        client = self._make_client(responses)
        auth = AuthManager(client, auth_checker=lambda u: True)
        with patch.object(auth, '_extract_csrf', return_value=(None, None)):
            with patch.object(auth, '_extract_submit', return_value=(None, None)):
                result = auth.auto_login("http://x/login.php", "admin", "pass")
        self.assertFalse(result)

    def test_login_success_protected_resource(self):
        responses = []
        login_get = MagicMock()
        login_get.success = True
        login_get.response.text = '<input name="username"><input name="password">'
        login_get.response.status_code = 200
        login_get.response.url = "http://x/login.php"
        responses.append(login_get)
        login_post = MagicMock()
        login_post.success = True
        login_post.response.text = "ok"
        login_post.response.status_code = 200
        login_post.response.url = "http://x/"
        responses.append(login_post)
        protected_ok = MagicMock()
        protected_ok.success = True
        protected_ok.response.text = '<a href="/logout">Logout</a> Welcome Dashboard'
        protected_ok.response.status_code = 200
        protected_ok.response.url = "http://x/dashboard"
        responses.append(protected_ok)
        client = self._make_client(responses)
        auth = AuthManager(client, auth_checker=lambda u: True)
        with patch.object(auth, '_extract_csrf', return_value=(None, None)):
            with patch.object(auth, '_extract_submit', return_value=(None, None)):
                result = auth.auto_login("http://x/login.php", "admin", "pass")
        self.assertTrue(result)

class TestMutatorLabMode(unittest.TestCase):
    def test_aggressive_blocked_without_env(self):
        os.environ.pop("TANPHA_LAB_MODE", None)
        from network.client import HTTPClient
        from network.config import HTTPConfig, EvasionLevel
        config = HTTPConfig(evasion_level=EvasionLevel.AGGRESSIVE, verify_tls=False)
        client = HTTPClient(config, lab_checker=lambda u: True)
        self.assertFalse(client._is_aggressive_authorized("http://x"))

    def test_aggressive_blocked_without_scope(self):
        os.environ["TANPHA_LAB_MODE"] = "1"
        from network.client import HTTPClient
        from network.config import HTTPConfig, EvasionLevel
        config = HTTPConfig(evasion_level=EvasionLevel.AGGRESSIVE, verify_tls=False)
        client = HTTPClient(config, lab_checker=lambda u: False)
        self.assertFalse(client._is_aggressive_authorized("http://x"))

    def test_aggressive_allowed_with_both(self):
        os.environ["TANPHA_LAB_MODE"] = "1"
        from network.client import HTTPClient
        from network.config import HTTPConfig, EvasionLevel
        config = HTTPConfig(evasion_level=EvasionLevel.AGGRESSIVE, verify_tls=False)
        client = HTTPClient(config, lab_checker=lambda u: True)
        self.assertTrue(client._is_aggressive_authorized("http://x"))

if __name__ == "__main__":
    unittest.main()
