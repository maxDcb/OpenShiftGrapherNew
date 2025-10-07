import types
from dataclasses import dataclass

import pytest

from OpenShiftGrapher import OpenShiftGrapher as osg


class DummyProxyManager:
    def __init__(self, url):
        self.url = url


@dataclass
class DummyConfig:
    host: str
    verify_ssl: bool = True
    token: str | None = None
    api_key: dict | None = None


class DummyApiClient:
    def __init__(self, config):
        self.config = config
        self.rest_client = types.SimpleNamespace(pool_manager=None)


class DummyCoreV1Api:
    def __init__(self, api_client):
        self.api_client = api_client


class DummyDynamicClient:
    def __init__(self, api_client):
        self.api_client = api_client
        self.resources = None


class FakeApiException(Exception):
    def __init__(self, status):
        super().__init__(f"status {status}")
        self.status = status


class RecordingResource:
    def __init__(self, to_raise=None, result=None):
        self.calls = 0
        self.to_raise = to_raise
        self.result = result if result is not None else object()

    def get(self):
        self.calls += 1
        if self.to_raise and self.calls <= len(self.to_raise):
            raise self.to_raise[self.calls - 1]
        return self.result


class SequentialResources:
    def __init__(self, sequence):
        self.sequence = list(sequence)

    def get(self, api_version=None, kind=None):  # noqa: D401 - signature matches production code
        return self.sequence.pop(0)


def test_refresh_token_returns_clean_input(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "  my-new-token  ")

    token = osg.refresh_token()

    assert token == "my-new-token"


def test_refresh_token_rejects_empty_input(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "")

    with pytest.raises(ValueError):
        osg.refresh_token()


@pytest.fixture
def patched_client(monkeypatch):
    client_stub = types.SimpleNamespace(
        ApiClient=DummyApiClient,
        CoreV1Api=DummyCoreV1Api,
        exceptions=types.SimpleNamespace(ApiException=FakeApiException),
    )
    monkeypatch.setattr(osg, "client", client_stub)
    return client_stub


def test_build_clients_with_proxy(monkeypatch, patched_client):
    config_instances = []

    def config_factory(host):
        cfg = DummyConfig(host)
        config_instances.append(cfg)
        return cfg

    monkeypatch.setattr(osg, "OCPLoginConfiguration", config_factory)

    dyn_instances = []

    def dynamic_factory(api_client):
        dyn = DummyDynamicClient(api_client)
        dyn_instances.append(dyn)
        return dyn

    monkeypatch.setattr(osg, "DynamicClient", dynamic_factory)

    proxy_instances = []
    monkeypatch.setattr(osg.urllib3, "ProxyManager", lambda url: proxy_instances.append(DummyProxyManager(url)) or proxy_instances[-1])

    dyn_client, v1 = osg.build_clients("token", "https://api", "https://proxy")

    assert isinstance(dyn_client, DummyDynamicClient)
    assert isinstance(v1, DummyCoreV1Api)
    assert config_instances and config_instances[0].host == "https://api"
    assert not config_instances[0].verify_ssl
    assert config_instances[0].token == "token"
    assert config_instances[0].api_key == {"authorization": "Bearer token"}
    assert isinstance(api_clients := dyn_instances[0].api_client, DummyApiClient)
    assert proxy_instances and proxy_instances[0].url == "https://proxy"
    assert api_clients.rest_client.pool_manager is proxy_instances[0]


def test_fetch_resource_success(monkeypatch, patched_client):
    resource = RecordingResource(result=["ok"])
    dyn_client = DummyDynamicClient(api_client=None)
    dyn_client.resources = SequentialResources([resource])

    result, returned_dyn, returned_token = osg.fetch_resource_with_refresh(
        dyn_client,
        api_key="token",
        hostApi="https://api",
        proxyUrl=None,
        api_version="v1",
        kind="Pod",
    )

    assert result == ["ok"]
    assert returned_dyn is dyn_client
    assert returned_token == "token"
    assert resource.calls == 1


def test_fetch_resource_refreshes_token(monkeypatch, patched_client):
    failing_resource = RecordingResource(to_raise=[FakeApiException(401)])
    successful_resource = RecordingResource(result=["ok"])

    first_dyn_client = DummyDynamicClient(api_client=None)
    first_dyn_client.resources = SequentialResources([failing_resource])

    refreshed_dyn_client = DummyDynamicClient(api_client=None)
    refreshed_dyn_client.resources = SequentialResources([successful_resource])

    refreshed_tokens = []
    monkeypatch.setattr(osg, "refresh_token", lambda: refreshed_tokens.append("new-token") or "new-token")

    build_calls = []

    def fake_build_clients(api_key, hostApi, proxyUrl):
        build_calls.append((api_key, hostApi, proxyUrl))
        return refreshed_dyn_client, object()

    monkeypatch.setattr(osg, "build_clients", fake_build_clients)

    result, returned_dyn, returned_token = osg.fetch_resource_with_refresh(
        first_dyn_client,
        api_key="expired-token",
        hostApi="https://api",
        proxyUrl="https://proxy",
        api_version="v1",
        kind="Pod",
    )

    assert result == ["ok"]
    assert returned_dyn is refreshed_dyn_client
    assert returned_token == "new-token"
    assert refreshed_tokens == ["new-token"]
    assert build_calls == [("new-token", "https://api", "https://proxy")]
    assert failing_resource.calls == 1
    assert successful_resource.calls == 1


def test_fetch_resource_propagates_other_errors(monkeypatch, patched_client):
    resource = RecordingResource(to_raise=[FakeApiException(500)])
    dyn_client = DummyDynamicClient(api_client=None)
    dyn_client.resources = SequentialResources([resource])

    with pytest.raises(FakeApiException):
        osg.fetch_resource_with_refresh(
            dyn_client,
            api_key="token",
            hostApi="https://api",
            proxyUrl=None,
            api_version="v1",
            kind="Pod",
        )

    assert resource.calls == 1

