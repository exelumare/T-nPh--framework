"""OOB Manager: Isolated external provider, routed via HTTPClient, correlated per attempt."""
import time
import uuid


class OOBManager:
    def __init__(self):
        self.token = None
        self.correlation_id = None
        self.url = None
        self._test_fixture = None

    def set_test_fixture(self, fixture_data):
        self._test_fixture = fixture_data

    def generate_payload(self, client, external_checker):
        if self._test_fixture is not None:
            self.token = "fixture_token"
            self.correlation_id = "TANPHA_FIXTURE_CORR"
            self.url = f"https://webhook.site/{self.token}?corr={self.correlation_id}"
            return self.url

        url = "https://webhook.site/token"
        if not external_checker or not external_checker(url):
            print("      [-] External API scope denied for OOB.")
            return None
        try:
            res = client.request("POST", url, auth_checker=external_checker)
            if res and res.success and res.response:
                if res.response.status_code in (200, 201):
                    data = res.response.json()
                    self.token = data.get("uuid")
                    self.correlation_id = f"TANPHA_{uuid.uuid4().hex[:12]}"
                    self.url = f"https://webhook.site/{self.token}?corr={self.correlation_id}"
                    print(f"      [+] OOB URL Generated: {self.url}")
                    return self.url
                elif res.response.status_code == 429:
                    print("      [-] Rate Limited. Waiting 5s...")
                    time.sleep(5)
        except Exception as e:
            print(f"      [-] OOB generation failed: {e}")
        return None

    def _parse_and_match(self, provider_data):
        if not self.correlation_id:
            return False
        if not isinstance(provider_data, list):
            return False
        for req in provider_data:
            if not isinstance(req, dict):
                continue
            serialized = str(req)
            if self.correlation_id in serialized:
                return True
        return False

    def check_hits(self, client, external_checker, timeout=15):
        if not self.token or not self.correlation_id:
            return False

        if self._test_fixture is not None:
            return self._parse_and_match(self._test_fixture)

        print(f"      [*] Waiting {timeout}s for correlated interaction...")
        time.sleep(timeout)
        url = f"https://webhook.site/token/{self.token}/requests"
        if not external_checker or not external_checker(url):
            return False
        try:
            res = client.request("GET", url, auth_checker=external_checker)
            if res and res.success and res.response and res.response.status_code == 200:
                provider_data = res.response.json().get("data", [])
                if self._parse_and_match(provider_data):
                    print(f"      [!] Correlated OOB Interaction Detected!")
                    return True
        except Exception:
            pass
        return False
