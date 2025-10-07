import os
import sys
import types

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def ensure_module(name):
    module = types.ModuleType(name)
    sys.modules[name] = module
    return module


if "urllib3" not in sys.modules:
    urllib3 = ensure_module("urllib3")
    urllib3.disable_warnings = lambda *args, **kwargs: None
    urllib3.ProxyManager = lambda url: types.SimpleNamespace(url=url)
    urllib3.exceptions = types.SimpleNamespace(
        InsecureRequestWarning=type("InsecureRequestWarning", (), {})
    )

if "py2neo" not in sys.modules:
    py2neo = ensure_module("py2neo")
    py2neo.Graph = lambda *args, **kwargs: types.SimpleNamespace(delete_all=lambda: None)
    py2neo.Node = type("Node", (), {})
    py2neo.Relationship = type("Relationship", (), {})
    py2neo.NodeMatcher = lambda *args, **kwargs: None

if "yaml" not in sys.modules:
    yaml = ensure_module("yaml")
    yaml.safe_dump = lambda *args, **kwargs: ""
    yaml.safe_load = lambda *args, **kwargs: {}

if "kubernetes" not in sys.modules:
    kubernetes = ensure_module("kubernetes")
    client_mod = ensure_module("kubernetes.client")

    class ApiException(Exception):
        def __init__(self, status=None, *args, **kwargs):
            super().__init__(*args)
            self.status = status

    client_mod.ApiClient = lambda *args, **kwargs: types.SimpleNamespace(rest_client=types.SimpleNamespace(pool_manager=None))
    client_mod.CoreV1Api = lambda *args, **kwargs: types.SimpleNamespace()
    client_mod.exceptions = types.SimpleNamespace(ApiException=ApiException)
    kubernetes.client = client_mod

if "openshift" not in sys.modules:
    openshift = ensure_module("openshift")
    dynamic_mod = ensure_module("openshift.dynamic")
    dynamic_mod.DynamicClient = lambda *args, **kwargs: types.SimpleNamespace(resources=None)
    openshift.dynamic = dynamic_mod

    helper_mod = ensure_module("openshift.helper")
    userpassauth_mod = ensure_module("openshift.helper.userpassauth")
    userpassauth_mod.OCPLoginConfiguration = lambda *args, **kwargs: types.SimpleNamespace()
    helper_mod.userpassauth = userpassauth_mod
    openshift.helper = helper_mod

if "progress" not in sys.modules:
    progress = ensure_module("progress")
    bar_mod = ensure_module("progress.bar")

    class DummyBar:
        def __init__(self, *args, **kwargs):
            pass

        def next(self):  # pragma: no cover - helper stub
            pass

        def finish(self):  # pragma: no cover - helper stub
            pass

    bar_mod.Bar = DummyBar
    progress.bar = bar_mod
