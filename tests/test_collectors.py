from types import SimpleNamespace

from OpenShiftGrapher.collectors import (
    CollectorContext,
    LookupTables,
    _build_lookup_tables,
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
