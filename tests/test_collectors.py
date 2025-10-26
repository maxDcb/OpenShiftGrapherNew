from types import SimpleNamespace

import OpenShiftGrapher.collectors as collectors_module

from OpenShiftGrapher.collectors import (
    CollectorContext,
    LookupTables,
    _build_lookup_tables,
    _collect_k8svaluespattern,
    _collect_keyword_values,
    _iterate_constrainttemplate_rego_sources,
    _should_collect,
)


def _list_from_items(*items):
    return SimpleNamespace(items=list(items))


def _metadata(**kwargs):
    return SimpleNamespace(**kwargs)


def test_should_collect_uses_aliases():
    assert _should_collect({"all"}, "oauth")
    assert _should_collect({"identity"}, "oauth", "identity")
    assert not _should_collect({"project"}, "oauth", "identity")


def test_build_lookup_tables_produces_expected_keys():
    project = SimpleNamespace(metadata=_metadata(name="proj", uid="proj-uid"))
    service_account = SimpleNamespace(
        metadata=_metadata(name="sa", namespace="ns", uid="sa-uid")
    )
    scc = SimpleNamespace(metadata=_metadata(name="restricted", uid="scc-uid"))
    role = SimpleNamespace(metadata=_metadata(name="role", namespace="ns", uid="role-uid"))
    clusterrole = SimpleNamespace(metadata=_metadata(name="cluster-role", uid="cr-uid"))
    user = SimpleNamespace(metadata=_metadata(name="alice", uid="user-uid"))
    group = SimpleNamespace(metadata=_metadata(name="team", uid="group-uid"))

    lookups = _build_lookup_tables(
        _list_from_items(project),
        _list_from_items(service_account),
        _list_from_items(scc),
        _list_from_items(role),
        _list_from_items(clusterrole),
        _list_from_items(user),
        _list_from_items(group),
    )

    assert lookups.project_by_name["proj"] is project
    assert lookups.serviceaccount_by_ns_name[("ns", "sa")] is service_account
    assert lookups.security_context_constraints_by_name["restricted"] is scc
    assert lookups.role_by_ns_name[("ns", "role")] is role
    assert lookups.clusterrole_by_name["cluster-role"] is clusterrole
    assert lookups.user_by_name["alice"] is user
    assert lookups.group_by_name["team"] is group


def test_collector_context_exposes_lookup_tables():
    lookups = LookupTables(
        project_by_name={"proj": "project"},
        serviceaccount_by_ns_name={("ns", "sa"): "service-account"},
        security_context_constraints_by_name={"restricted": "scc"},
        role_by_ns_name={("ns", "role"): "role"},
        clusterrole_by_name={"cluster-role": "cluster-role"},
        user_by_name={"alice": "user"},
        group_by_name={"team": "group"},
    )

    context = CollectorContext(
        graph=object(),
        collector={"all"},
        release=True,
        oauth_list=None,
        identity_list=None,
        project_list=None,
        serviceAccount_list=None,
        security_context_constraints_list=None,
        role_list=None,
        clusterrole_list=None,
        user_list=None,
        group_list=None,
        roleBinding_list=None,
        clusterRoleBinding_list=None,
        route_list=None,
        pod_list=None,
        kyverno_logs=None,
        configmap_list=None,
        constraintTemplate_list=None,
        k8sValuesPattern_list=None,
        validatingWebhookConfiguration_list=None,
        mutatingWebhookConfiguration_list=None,
        clusterPolicy_list=None,
        lookups=lookups,
    )

    assert context.project_by_name["proj"] == "project"
    assert context.serviceaccount_by_ns_name[("ns", "sa")] == "service-account"
    assert context.security_context_constraints_by_name["restricted"] == "scc"
    assert context.role_by_ns_name[("ns", "role")] == "role"
    assert context.clusterrole_by_name["cluster-role"] == "cluster-role"
    assert context.user_by_name["alice"] == "user"
    assert context.group_by_name["team"] == "group"


def test_collect_keyword_values_extracts_nested_exclusions():
    additional_match = SimpleNamespace(
        clusterExclusionsName="namespace-denied-name-pattern",
        accountSelector=SimpleNamespace(
            excludedAccounts=[
                "system:admin",
                "system:serviceaccount:openshift:router",
            ],
            excludedClusterRoles=["cluster-admin"],
        ),
        namespaceSelector=SimpleNamespace(
            excludedNamespaces=["openshift-monitoring"],
        ),
        otherField="should-ignore",
    )

    result = _collect_keyword_values(additional_match, ("exclude", "exclusion"))

    assert result["clusterExclusionsName"] == ["namespace-denied-name-pattern"]
    assert result["excludedAccounts"] == [
        "system:admin",
        "system:serviceaccount:openshift:router",
    ]
    assert result["excludedClusterRoles"] == ["cluster-admin"]
    assert result["excludedNamespaces"] == ["openshift-monitoring"]


def test_iterate_constrainttemplate_rego_sources_handles_code_blocks_and_libs():
    target = SimpleNamespace(
        rego=None,
        code=[
            SimpleNamespace(
                engine="Rego",
                source=SimpleNamespace(rego="package owners\nviolation[{}] { true }"),
            ),
            SimpleNamespace(
                engine="not-rego",
                source=SimpleNamespace(rego="package skip"),
            ),
            SimpleNamespace(
                engine="rego",
                rego="package secondary\nallow { true }",
            ),
        ],
        libs=[
            SimpleNamespace(
                source=SimpleNamespace(rego="package lib.helpers\nallow { false }"),
            )
        ],
    )

    snippets = list(_iterate_constrainttemplate_rego_sources(target))

    assert snippets == [
        "package owners\nviolation[{}] { true }",
        "package secondary\nallow { true }",
        "package lib.helpers\nallow { false }",
    ]


def test_collect_k8svaluespattern_records_exclusions_and_protections(monkeypatch):
    class DummyBar:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def next(self):
            pass

    class DummyNode(dict):
        def __init__(self, label, **properties):  # pylint: disable=unused-argument
            super().__init__(properties)

    class FakeMatch:
        def count(self):
            return 0

    class FakeNodes:
        def match(self, _label):
            return FakeMatch()

    class FakeTx:
        def __init__(self, store):
            self.store = store

        def merge(self, node):
            self.store.append(node)

    class FakeGraph:
        def __init__(self):
            self.created_nodes = []
            self.nodes = FakeNodes()

        def begin(self):
            return FakeTx(self.created_nodes)

        def commit(self, _tx):
            pass

    monkeypatch.setattr(collectors_module, "Bar", DummyBar)
    monkeypatch.setattr(collectors_module, "Node", DummyNode)

    graph = FakeGraph()
    lookups = LookupTables(
        project_by_name={},
        serviceaccount_by_ns_name={},
        security_context_constraints_by_name={},
        role_by_ns_name={},
        clusterrole_by_name={},
        user_by_name={},
        group_by_name={},
    )

    values_pattern = SimpleNamespace(
        metadata=SimpleNamespace(name="namespace-denied-name-pattern", uid="uid-123"),
        spec=SimpleNamespace(
            enforcementAction="scoped",
            scopedEnforcementActions=[
                SimpleNamespace(
                    action="deny",
                    enforcementPoints=[
                        SimpleNamespace(name="validation.gatekeeper.sh"),
                    ],
                )
            ],
            match=SimpleNamespace(
                kinds=[
                    SimpleNamespace(apiGroups=[""], kinds=["Namespace"]),
                    SimpleNamespace(apiGroups=["apps"], kinds=["Deployment"]),
                ]
            ),
            parameters=SimpleNamespace(
                violationDocumentation=SimpleNamespace(
                    linkToDocumentation="https://toto.atlassian.net/wiki/x/uvrPew",
                ),
                additionalMatch=SimpleNamespace(
                    clusterExclusionsName="namespace-denied-name-pattern",
                    accountSelector=SimpleNamespace(
                        excludedAccounts=[
                            "system:admin",
                            "system:serviceaccount:openshift:router",
                        ],
                        excludedClusterRoles=["cluster-admin"],
                    ),
                    namespaceSelector=SimpleNamespace(
                        excludedNamespaces=["openshift-monitoring"],
                    ),
                ),
                valuesPatterns=[
                    SimpleNamespace(
                        parent="metadata",
                        patterns=[
                            SimpleNamespace(
                                field="name",
                                deny=True,
                                globs=["openshift*", "stackrox", "kube-*"],
                            ),
                            SimpleNamespace(
                                field="name",
                                deny=True,
                                values=["system"],
                            ),
                        ],
                    )
                ],
            ),
        ),
        _source_path="/tmp/namespace-denied-name-pattern.yaml",
    )

    context = CollectorContext(
        graph=graph,
        collector={"k8svaluespattern"},
        release=True,
        oauth_list=None,
        identity_list=None,
        project_list=None,
        serviceAccount_list=None,
        security_context_constraints_list=None,
        role_list=None,
        clusterrole_list=None,
        user_list=None,
        group_list=None,
        roleBinding_list=None,
        clusterRoleBinding_list=None,
        route_list=None,
        pod_list=None,
        kyverno_logs=None,
        configmap_list=None,
        constraintTemplate_list=None,
        k8sValuesPattern_list=SimpleNamespace(
            items=[values_pattern],
            _source_directory="/manifests",
        ),
        validatingWebhookConfiguration_list=None,
        mutatingWebhookConfiguration_list=None,
        clusterPolicy_list=None,
        lookups=lookups,
    )

    _collect_k8svaluespattern(context)

    assert len(graph.created_nodes) == 1
    node = graph.created_nodes[0]

    assert node["excludedSummary"] == (
        "clusterExclusionsName: namespace-denied-name-pattern; "
        "excludedAccounts: system:admin, system:serviceaccount:openshift:router; "
        "excludedClusterRoles: cluster-admin; excludedNamespaces: openshift-monitoring"
    )
    assert node["excludedAccounts"] == "system:admin, system:serviceaccount:openshift:router"
    assert node["excludedClusterRoles"] == "cluster-admin"
    assert node["excludedNamespaces"] == "openshift-monitoring"
    assert node["clusterExclusionsName"] == "namespace-denied-name-pattern"
    assert node["protectedGlobs"] == "kube-*, openshift*, stackrox"
    assert node["protectedValues"] == "system"
    assert node["protectedSummary"] == (
        "globs: kube-*, openshift*, stackrox; values: system"
    )
    assert node["matchKinds"] == "Namespace, apps/Deployment"
    assert "🚫 2 deny patterns" in node["risk"]
