from types import SimpleNamespace
import random

import pytest

from curl_cffi import requests

from network.client import HTTPClient
from network.config import HTTPConfig, EvasionLevel
from network.exceptions import ScopeViolationError

from network.result import (
    NormalizedResponse,
    RequestResult,
)

from modules.sqli import SQLInjectionModule
from modules.cmd_injection import CommandInjectionModule
from modules.lfi import LFIModule
from core.context import Evidence

# --------------------------------------------------
# Fixtures / helpers
# --------------------------------------------------

class FakeRawResponse:
    """Simulasi response dari HTTP transport."""

    def __init__(
        self,
        status_code=200,
        text="OK",
        headers=None,
        url="https://lab.example/test",
        content=None,
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.content = (
            content if content is not None else text.encode()
        )
        self.closed = False

    def close(self):
        self.closed = True


def make_response(
    status_code=200,
    text="OK",
    headers=None,
):
    raw = FakeRawResponse(
        status_code=status_code,
        text=text,
        headers=headers or {},
    )
    return NormalizedResponse(raw)


def make_request_result(
    status_code=200,
    text="OK",
    headers=None,
):
    return RequestResult(
        response=make_response(
            status_code=status_code,
            text=text,
            headers=headers,
        ),
        attempts=1,
        elapsed=0.01,
    )


def make_context():
    return SimpleNamespace(
        target=SimpleNamespace(
            base_url="https://lab.example/test"
        )
    )

def make_transport_test_client(monkeypatch, responses, max_attempts=2):
    client = object.__new__(HTTPClient)

    client.config = HTTPConfig(
        delay=0,
        max_attempts=max_attempts,
        evasion_level=EvasionLevel.NONE,
    )

    client._verify_tls = True
    client._rng = random.Random(1)

    client.mutator = SimpleNamespace(
        level=EvasionLevel.AGGRESSIVE
    )

    response_iterator = iter(responses)

    def fake_request(**kwargs):
        item = next(response_iterator)

        if isinstance(item, BaseException):
            raise item

        return item

    client.session = SimpleNamespace(
        request=fake_request
    )

    client._check_dns_rebinding = (
        lambda url, auth_checker: (True, "")
    )

    monkeypatch.setattr(
        "network.client.time.sleep",
        lambda *_: None,
    )

    return client
# --------------------------------------------------
# 1. NormalizedResponse contract
# --------------------------------------------------

def test_normalized_response_attributes():
    response = make_response(
        status_code=500,
        text="Internal Server Error",
        headers={
            "Content-Type": "text/html",
            "Set-Cookie": "session=test",
        },
    )

    assert response.status_code == 500
    assert response.text == "Internal Server Error"
    assert isinstance(response.content, bytes)
    assert response.url == "https://lab.example/test"

    assert response.headers.get("content-type") == "text/html"
    assert response.headers.get("CONTENT-TYPE") == "text/html"
    assert response.headers.get("set-cookie") == "session=test"


def test_request_result_success():
    result = make_request_result()

    assert result.success is True
    assert result.response is not None
    assert result.response.status_code == 200
    assert result.response.text == "OK"


def test_request_result_error():
    result = RequestResult(
        response=make_response(),
        error=RuntimeError("simulated error"),
    )

    assert result.success is False


# --------------------------------------------------
# 2. SQLi parser and Evidence
# --------------------------------------------------

def test_sqli_error_signature_and_evidence():
    module = object.__new__(SQLInjectionModule)

    baseline = make_response(
        status_code=200,
        text="Normal page",
    )

    simulated_error = make_response(
        status_code=500,
        text="SQL syntax error detected",
    )

    responses = iter([baseline, simulated_error])

    def fake_sender(_value):
        return next(responses)

    evidence = module._test_boolean_error(
        make_context(),
        "test_parameter",
        fake_sender,
    )

    assert isinstance(evidence, Evidence)
    assert evidence.module_id == "sqli"
    assert evidence.reason_code == "ERROR_BASED"
    assert evidence.assess_payload is not None


# --------------------------------------------------
# 3. CMD parser and Evidence
# --------------------------------------------------

def test_cmd_output_parser():
    module = object.__new__(CommandInjectionModule)

    assert module._is_cmd_output("uid=1000(test) gid=1000(test)")
    assert module._is_cmd_output("Linux test-host")
    assert not module._is_cmd_output("Normal application response")


def test_cmd_request_result_response_access():
    result = make_request_result(
        status_code=200,
        text="uid=1000(test) gid=1000(test)",
    )

    assert result.success
    module_text = result.response.text

    assert module_text
    assert "uid=" in module_text

    module = object.__new__(CommandInjectionModule)
    assert module._is_cmd_output(result.response.text)


def test_cmd_evidence_creation():
    module = object.__new__(CommandInjectionModule)

    class FakeAI:
        def analyze(self, **kwargs):
            return '{"is_vulnerable": false}'

    module.ai = FakeAI()

    pool = []

    module._record_evidence(
        pool=pool,
        context=make_context(),
        param="test_parameter",
        payload="mock-input",
        baseline_text="normal response",
        res_text="simulated anomaly",
        injection_point="PARAM",
    )

    assert len(pool) == 1
    assert isinstance(pool[0], Evidence)
    assert pool[0].module_id == "cmd"
    assert pool[0].reason_code == "AI_PIVOT"


# --------------------------------------------------
# 4. LFI parser and Evidence
# --------------------------------------------------

def test_lfi_output_parser():
    module = object.__new__(LFIModule)

    is_vulnerable, reason = module._is_lfi_output(
        "root:x:0:0:root:/root:/bin/bash"
    )

    assert is_vulnerable is True
    assert reason == "FILE_READ"

    is_vulnerable, _ = module._is_lfi_output(
        "Normal application response"
    )

    assert is_vulnerable is False


def test_lfi_evidence_creation():
    module = object.__new__(LFIModule)

    simulated_response = make_response(
        status_code=200,
        text="root:x:0:0:root:/root:/bin/bash",
    )

    def fake_sender(_payload):
        return simulated_response

    evidence = module._test_lfi(
        make_context(),
        "test_parameter",
        fake_sender,
    )

    assert isinstance(evidence, Evidence)
    assert evidence.module_id == "lfi"
    assert evidence.reason_code == "LFI_CONFIRMED"
    assert evidence.assess_payload is not None


# --------------------------------------------------
# 5. Shared response contract
# --------------------------------------------------

@pytest.mark.parametrize(
    "module_name",
    ["sqli", "cmd", "lfi"],
)
def test_response_contract_for_all_modules(module_name):
    result = make_request_result(
        status_code=200,
        text="Mock response",
        headers={
            "Content-Type": "text/plain",
            "X-Test": "works",
        },
    )

    response = result.response

    assert response is not None
    assert isinstance(response.status_code, int)
    assert isinstance(response.text, str)
    assert isinstance(response.content, bytes)
    assert isinstance(response.url, str)

    assert response.headers.get("content-type") == "text/plain"
    assert response.headers.get("X-TEST") == "works"

@pytest.mark.parametrize(
    "status_code, expected_retry_reason",
    [
        (200, None),
        (500, "http_500"),
    ],
)
def test_http_client_closes_raw_response(
    status_code,
    expected_retry_reason,
):
    raw_response = FakeRawResponse(
        status_code=status_code,
        text="Response remains readable",
        headers={"Content-Type": "text/plain"},
    )

    client = object.__new__(HTTPClient)

    client.config = SimpleNamespace(
        evasion_level=EvasionLevel.STANDARD,
        max_attempts=1,
        delay=0,
        user_agent="test-agent",
    )

    client._verify_tls = True
    client._rng = random.Random(1)

    client.mutator = SimpleNamespace(
        level=EvasionLevel.STANDARD,
    )

    client.session = SimpleNamespace(
        request=lambda **kwargs: raw_response,
    )

    client._check_dns_rebinding = (
        lambda url, auth_checker: (True, "")
    )

    result = client.request(
        "GET",
        "https://lab.example/test",
        auth_checker=lambda url: True,
        bypass_mutation=True,
    )

    assert result.response is not None
    assert result.response.status_code == status_code
    assert result.retry_reason == expected_retry_reason

    # Raw transport response harus sudah ditutup.
    assert raw_response.closed is True

    # Data hasil normalisasi tetap tersedia.
    assert result.response.text == "Response remains readable"
    assert result.response.content == b"Response remains readable"
    assert result.response.headers.get("content-type") == "text/plain"

def test_transport_exception_retries_and_recovers(monkeypatch):
    raw = FakeRawResponse(
        status_code=200,
        text="Recovered",
    )

    client = make_transport_test_client(
        monkeypatch,
        [
            requests.exceptions.RequestException("temporary error"),
            raw,
        ],
    )

    result = client.request(
        "GET",
        "https://lab.example/test",
        auth_checker=lambda url: True,
        bypass_mutation=True,
    )

    assert result.success is True
    assert result.attempts == 2
    assert result.error is None
    assert result.retry_reason is None
    assert result.response.text == "Recovered"
    assert raw.closed is True

    # Level mutator harus dikembalikan.
    assert client.mutator.level == EvasionLevel.AGGRESSIVE


def test_retryable_http_response_is_closed(monkeypatch):
    retry_response = FakeRawResponse(
        status_code=503,
        text="Service Unavailable",
    )

    final_response = FakeRawResponse(
        status_code=200,
        text="Recovered",
    )

    client = make_transport_test_client(
        monkeypatch,
        [retry_response, final_response],
    )

    result = client.request(
        "GET",
        "https://lab.example/test",
        auth_checker=lambda url: True,
        bypass_mutation=True,
    )

    assert result.success is True
    assert result.attempts == 2
    assert retry_response.closed is True
    assert final_response.closed is True
    assert result.response.status_code == 200
    assert result.error is None
    assert result.retry_reason is None


def test_missing_auth_checker_fails_closed():
    client = object.__new__(HTTPClient)

    request_called = False

    def fake_request(**kwargs):
        nonlocal request_called
        request_called = True

    client.session = SimpleNamespace(
        request=fake_request
    )

    result = client.request(
        "GET",
        "https://lab.example/test",
    )

    assert result.success is False
    assert isinstance(result.error, ScopeViolationError)
    assert result.retry_reason == "MISSING_AUTH_CHECKER"
    assert request_called is False


def test_auth_checker_exception_prevents_request(monkeypatch):
    client = make_transport_test_client(
        monkeypatch,
        [],
    )

    request_called = False

    def fake_request(**kwargs):
        nonlocal request_called
        request_called = True

    client.session.request = fake_request

    def failing_auth_checker(url):
        raise RuntimeError("simulated checker failure")

    result = client.request(
        "GET",
        "https://lab.example/test",
        auth_checker=failing_auth_checker,
        bypass_mutation=True,
    )

    assert result.success is False
    assert isinstance(result.error, ScopeViolationError)
    assert result.retry_reason == "AUTH_CHECKER_ERROR"
    assert request_called is False

    assert client.mutator.level == EvasionLevel.AGGRESSIVE


def test_redirect_response_is_closed_and_followed(monkeypatch):
    redirect_response = FakeRawResponse(
        status_code=302,
        text="Redirect",
        headers={"Location": "/final"},
    )

    final_response = FakeRawResponse(
        status_code=200,
        text="Final page",
    )

    client = make_transport_test_client(
        monkeypatch,
        [redirect_response, final_response],
    )

    result = client.request(
        "GET",
        "https://lab.example/start",
        auth_checker=lambda url: True,
        bypass_mutation=True,
    )

    assert result.success is True
    assert result.response.status_code == 200
    assert result.response.text == "Final page"
    assert redirect_response.closed is True
    assert final_response.closed is True
    assert result.error is None
    assert result.retry_reason is None
    assert result.attempts == 1

def test_redirect_without_location_is_closed(monkeypatch):
    redirect_response = FakeRawResponse(
        status_code=302,
        text="Missing Location",
    )

    client = make_transport_test_client(
        monkeypatch,
        [redirect_response],
    )

    result = client.request(
        "GET",
        "https://lab.example/start",
        auth_checker=lambda url: True,
        bypass_mutation=True,
    )

    assert result.success is False
    assert isinstance(result.error, ScopeViolationError)
    assert result.retry_reason == "SCOPE_VIOLATION"
    assert redirect_response.closed is True
    assert result.attempts == 1

def test_redirect_limit_closes_responses(monkeypatch):
    redirect_responses = [
        FakeRawResponse(
            status_code=302,
            text="Redirect",
            headers={"Location": "/next"},
        )
        for _ in range(6)
    ]

    client = make_transport_test_client(
        monkeypatch,
        redirect_responses,
    )

    result = client.request(
        "GET",
        "https://lab.example/start",
        auth_checker=lambda url: True,
        bypass_mutation=True,
    )

    assert result.success is False
    assert type(result.error).__name__ == "RedirectLimitExceeded"
    assert result.retry_reason == "REDIRECT_LIMIT_EXCEEDED"
    assert result.attempts == 1
    assert result.response is None

    assert all(
        response.closed
        for response in redirect_responses
    )


def test_out_of_scope_redirect_is_closed(monkeypatch):
    redirect_response = FakeRawResponse(
        status_code=302,
        text="Redirect",
        headers={"Location": "https://outside.example/page"},
    )

    client = make_transport_test_client(
        monkeypatch,
        [redirect_response],
    )

    def auth_checker(url):
        return url == "https://lab.example/start"

    result = client.request(
        "GET",
        "https://lab.example/start",
        auth_checker=auth_checker,
        bypass_mutation=True,
    )

    assert result.success is False
    assert isinstance(result.error, ScopeViolationError)
    assert result.retry_reason == "SCOPE_VIOLATION"
    assert result.attempts == 1
    assert redirect_response.closed is True

@pytest.mark.parametrize("status_code", [300, 304])
def test_non_comparable_response_is_closed(monkeypatch, status_code):
    response = FakeRawResponse(
        status_code=status_code,
        text="Non-comparable response",
    )
    client = make_transport_test_client(
        monkeypatch,
        [response],
    )

    result = client.request(
        "GET",
        "https://lab.example/start",
        auth_checker=lambda url: True,
        bypass_mutation=True,
    )

    assert result.success is False
    assert type(result.error).__name__ == "NonComparableResponseError"
    assert result.retry_reason == f"HTTP_{status_code}_NON_COMPARABLE"
    assert result.attempts == 1
    assert response.closed is True


def test_dns_failure_on_redirect_closes_response(monkeypatch):
    redirect_response = FakeRawResponse(
        status_code=302,
        text="Redirect",
        headers={"Location": "/next"},
    )
    client = make_transport_test_client(
        monkeypatch,
        [redirect_response],
    )

    monkeypatch.setattr(
        "network.client.time.perf_counter",
        iter([100.0, 102.5]).__next__,
    )

    client._check_dns_rebinding = lambda url, auth_checker: (
        url.endswith("/start"),
        "TEST_DNS_FAILURE",
    )

    result = client.request(
        "GET",
        "https://lab.example/start",
        auth_checker=lambda url: True,
        bypass_mutation=True,
    )

    assert result.success is False
    assert isinstance(result.error, ScopeViolationError)
    assert result.retry_reason == "TEST_DNS_FAILURE"
    assert result.attempts == 1
    assert redirect_response.closed is True
    assert result.elapsed == 2.5


def test_redirect_auth_checker_exception_closes_response(monkeypatch):
    redirect_response = FakeRawResponse(
        status_code=302,
        text="Redirect",
        headers={"Location": "/next"},
    )
    client = make_transport_test_client(
        monkeypatch,
        [redirect_response],
    )

    def auth_checker(url):
        if url.endswith("/start"):
            return True
        raise RuntimeError("Simulated auth checker failure")

    result = client.request(
        "GET",
        "https://lab.example/start",
        auth_checker=auth_checker,
        bypass_mutation=True,
    )

    assert result.success is False
    assert isinstance(result.error, ScopeViolationError)
    assert result.retry_reason == "AUTH_CHECKER_ERROR"
    assert result.attempts == 1
    assert redirect_response.closed is True


def test_invalid_redirect_url_closes_response(monkeypatch):
    redirect_response = FakeRawResponse(
        status_code=302,
        text="Redirect",
        headers={"Location": "http://[invalid"},
    )
    client = make_transport_test_client(
        monkeypatch,
        [redirect_response],
    )

    result = client.request(
        "GET",
        "https://lab.example/start",
        auth_checker=lambda url: True,
        bypass_mutation=True,
    )

    assert result.success is False
    assert isinstance(result.error, ScopeViolationError)
    assert result.retry_reason == "INVALID_URL"
    assert result.attempts == 1
    assert redirect_response.closed is True

@pytest.mark.parametrize("status_code", [429, 502, 503, 504])
def test_retry_exhaustion_preserves_last_http_response(
    monkeypatch,
    status_code,
):
    responses = [
        FakeRawResponse(
            status_code=status_code,
            text=f"HTTP {status_code} response",
        )
        for _ in range(2)
    ]

    client = make_transport_test_client(
        monkeypatch,
        responses,
        max_attempts=2,
    )

    sleep_calls = []
    monkeypatch.setattr(
        "network.client.time.sleep",
        lambda duration: sleep_calls.append(duration),
    )

    result = client.request(
        "GET",
        "https://lab.example/test",
        auth_checker=lambda url: True,
        bypass_mutation=True,
    )

    # Response terakhir tetap tersedia setelah retry habis.
    assert result.response is not None
    assert result.response.status_code == status_code
    assert result.response.text == f"HTTP {status_code} response"

    # HTTP response berarti transport berhasil.
    assert result.success is True
    assert result.error is None

    # Dua percobaan sudah dilakukan.
    assert result.attempts == 2

    # Semua raw response sudah ditutup.
    assert all(response.closed for response in responses)

    # Tidak boleh tidur lagi setelah percobaan terakhir.
    assert len(sleep_calls) == 1

    # Retry reason tetap mencatat status yang memicu retry.
    assert result.retry_reason == f"http_{status_code}"

@pytest.mark.parametrize(
    "url, auth_checker, expected_reason",
    [
        (
            "https://lab.example/test",
            None,
            "MISSING_AUTH_CHECKER",
        ),
        (
            "not-a-valid-url",
            lambda url: True,
            "INVALID_URL",
        ),
    ],
)
def test_early_validation_returns_elapsed(
    monkeypatch,
    url,
    auth_checker,
    expected_reason,
):
    client = object.__new__(HTTPClient)

    clock = iter([100.0, 102.5])
    monkeypatch.setattr(
        "network.client.time.perf_counter",
        lambda: next(clock),
    )

    result = client.request(
        "GET",
        url,
        auth_checker=auth_checker,
    )

    assert result.success is False
    assert result.error is not None
    assert result.retry_reason == expected_reason
    assert result.attempts == 0
    assert result.elapsed == 2.5


def test_dns_failure_return_sets_elapsed(monkeypatch):
    client = make_transport_test_client(
        monkeypatch,
        [],
    )

    monkeypatch.setattr(
        "network.client.time.perf_counter",
        iter([100.0, 102.5]).__next__,
    )

    client._check_dns_rebinding = lambda url, auth_checker: (
        False,
        "TEST_DNS_FAILURE",
    )

    result = client.request(
        "GET",
        "https://lab.example/test",
        auth_checker=lambda url: True,
        bypass_mutation=True,
    )

    assert result.success is False
    assert result.retry_reason == "TEST_DNS_FAILURE"
    assert result.attempts == 1
    assert result.elapsed == 2.5


def test_auth_checker_exception_return_sets_elapsed(monkeypatch):
    client = make_transport_test_client(
        monkeypatch,
        [],
    )

    monkeypatch.setattr(
        "network.client.time.perf_counter",
        iter([100.0, 102.5]).__next__,
    )

    def failing_auth_checker(url):
        raise RuntimeError("Simulated failure")

    result = client.request(
        "GET",
        "https://lab.example/test",
        auth_checker=failing_auth_checker,
        bypass_mutation=True,
    )

    assert result.success is False
    assert result.retry_reason == "AUTH_CHECKER_ERROR"
    assert result.attempts == 1
    assert result.elapsed == 2.5


def test_scope_violation_return_sets_elapsed(monkeypatch):
    client = make_transport_test_client(
        monkeypatch,
        [],
    )

    monkeypatch.setattr(
        "network.client.time.perf_counter",
        iter([100.0, 102.5]).__next__,
    )

    result = client.request(
        "GET",
        "https://lab.example/test",
        auth_checker=lambda url: False,
        bypass_mutation=True,
    )

    assert result.success is False
    assert result.retry_reason == "SCOPE_VIOLATION"
    assert result.attempts == 1
    assert result.elapsed == 2.5


def test_invalid_mutated_url_return_sets_elapsed(monkeypatch):
    client = make_transport_test_client(
        monkeypatch,
        [],
    )

    monkeypatch.setattr(
        "network.client.time.perf_counter",
        iter([100.0, 102.5]).__next__,
    )

    client.mutator.mutate_url_parameters = (
        lambda url, target_param: "invalid-mutated-url"
    )

    client.mutator.mutate_headers = (
        lambda headers: headers
    )

    result = client.request(
        "GET",
        "https://lab.example/test",
        auth_checker=lambda url: True,
    )

    assert result.success is False
    assert result.retry_reason == "INVALID_URL"
    assert result.attempts == 1
    assert result.elapsed == 2.5


def test_request_exception_retry_exhaustion_consistency(monkeypatch):
    client = make_transport_test_client(
        monkeypatch,
        [],
        max_attempts=2,
    )

    request_calls = []

    def failing_request(**kwargs):
        request_calls.append(kwargs)
        raise requests.exceptions.ConnectionError(
            "Simulated connection failure"
        )

    client.session.request = failing_request

    sleep_calls = []
    monkeypatch.setattr(
        "network.client.time.sleep",
        lambda duration: sleep_calls.append(duration),
    )

    result = client.request(
        "GET",
        "https://lab.example/test",
        auth_checker=lambda url: True,
        bypass_mutation=True,
    )

    assert result.success is False
    assert result.response is None
    assert isinstance(
        result.error,
        requests.exceptions.ConnectionError,
    )
    assert result.retry_reason == "ConnectionError"
    assert result.attempts == 2
    assert len(request_calls) == 2
    assert len(sleep_calls) == 1



def test_unexpected_exception_result_consistency(monkeypatch):
    client = make_transport_test_client(
        monkeypatch,
        [],
        max_attempts=2,
    )

    def unexpected_failure(**kwargs):
        raise RuntimeError("Simulated unexpected failure")

    client.session.request = unexpected_failure

    result = client.request(
        "GET",
        "https://lab.example/test",
        auth_checker=lambda url: True,
        bypass_mutation=True,
    )

    assert result.success is False
    assert result.response is None
    assert isinstance(result.error, RuntimeError)
    assert result.retry_reason == "UNEXPECTED_RuntimeError"
    assert result.attempts == 1
