"""Collector helpers for OpenShiftGrapher."""

from __future__ import annotations

import os
import re
import sys
from contextlib import contextmanager
from typing import Iterable, Iterator, List, MutableMapping, Optional, Sequence

from progress.bar import Bar
from py2neo import Graph, Node, Relationship, NodeMatcher


@contextmanager
def _progress_bar(label: str, items: Sequence) -> Iterator[Optional[Bar]]:
    """Yield a progress bar for ``items`` if the collection is not empty."""
    total = len(items)
    if total == 0:
        print(f"No {label} resources found.")
        yield None
        return

    with Bar(label, max=total) as bar:
        yield bar


def _handle_exception(exc: Exception, release: bool) -> None:
    if release:
        print(exc)
        return

    exc_type, _, exc_tb = sys.exc_info()
    if exc_tb is None:
        raise exc

    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    print(exc_type, fname, exc_tb.tb_lineno)
    print("Error:", exc)
    sys.exit(1)


def _safe_items(collection) -> List:
    """Return a list for ``collection.items`` handling None gracefully."""
    items = getattr(collection, "items", None)
    if not items:
        return []
    return list(items)


PRIVILEGED_CLUSTER_ROLES = {
    "cluster-admin",
    "admin",
    "edit",
    "self-provisioner",
}

PRIVILEGED_NAMESPACE_ROLES = {"admin", "edit"}

BROAD_GROUP_SUBJECTS = {
    "system:authenticated",
    "system:unauthenticated",
    "system:serviceaccounts",
}

BROAD_GROUP_PREFIXES = (
    "system:serviceaccounts:",
    "system:authenticated:",
    "system:unauthenticated:",
)

BROAD_USERS = {"system:anonymous"}

DEFAULT_SA_NAMES = {"default"}


def _deduplicate_preserve_order(items: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def assess_binding_risk(role_kind, role_name, subjects, binding_scope):
    reasons = []

    if role_kind == "ClusterRole" and role_name in PRIVILEGED_CLUSTER_ROLES:
        reasons.append(
            f'ClusterRole "{role_name}" grants elevated cluster permissions'
        )

    if role_kind == "Role" and role_name in PRIVILEGED_NAMESPACE_ROLES:
        reasons.append(
            f'Role "{role_name}" allows broad management within the namespace'
        )

    if binding_scope == "RoleBinding" and role_kind == "ClusterRole":
        reasons.append(
            "ClusterRole referenced from a RoleBinding exposes cluster privileges inside the namespace"
        )

    if binding_scope == "ClusterRoleBinding" and role_kind == "Role":
        reasons.append(
            "ClusterRoleBinding references a namespaced Role, applying it cluster-wide"
        )

    for subject in subjects:
        kind = subject["kind"]
        name = subject["name"]
        effective_ns = subject.get("effective_namespace")

        if kind == "Group":
            if name in BROAD_GROUP_SUBJECTS:
                reasons.append(
                    f'Group "{name}" represents a wide population of users or service accounts'
                )
            else:
                for prefix in BROAD_GROUP_PREFIXES:
                    if name.startswith(prefix):
                        reasons.append(
                            f'Group "{name}" expands to a large set of service accounts'
                        )
                        break

        elif kind == "User" and name in BROAD_USERS:
            reasons.append(
                f'User "{name}" is assigned to unauthenticated requests'
            )

        elif kind == "ServiceAccount" and name in DEFAULT_SA_NAMES:
            if effective_ns:
                reasons.append(
                    f'Default service account in namespace "{effective_ns}" receives elevated privileges'
                )
            else:
                reasons.append(
                    "Default service account receives elevated privileges"
                )

    return _deduplicate_preserve_order(reasons)


def describe_subject(subject, binding_namespace):
    kind = subject["kind"]
    name = subject["name"]
    effective_ns = subject.get("effective_namespace") or binding_namespace

    if kind == "ServiceAccount":
        if effective_ns:
            return f"ServiceAccount {effective_ns}/{name}"
        return f"ServiceAccount {name}"

    if kind in {"Group", "User"}:
        return f"{kind} {name}"

    if effective_ns:
        return f"{kind} {effective_ns}/{name}"

    return f"{kind} {name}"


def build_binding_context(role_kind, role_name, subjects, binding_namespace, danger_reasons):
    parts = [f"RoleRef: {role_kind} {role_name}"]

    if subjects:
        subject_descriptions = [
            describe_subject(subject, binding_namespace) for subject in subjects
        ]
        parts.append("Subjects: " + ", ".join(subject_descriptions))
    else:
        parts.append("Subjects: none")

    if danger_reasons:
        parts.append("Danger: " + "; ".join(danger_reasons))

    return " | ".join(parts)


def import_projects(graph: Graph, collector, project_list, release: bool) -> List:
    print("#### Project ####")

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("Project").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} Project nodes, skipping import.")
        return _safe_items(project_list)

    if "all" not in collector and "project" not in collector:
        return _safe_items(project_list)

    project_items = _safe_items(project_list)
    with _progress_bar("Project", project_items) as bar:
        if bar is None:
            return project_items
        for enum in project_items:
            try:
                tx = graph.begin()
                a = Node("Project", name=enum.metadata.name, uid=enum.metadata.uid)
                a.__primarylabel__ = "Project"
                a.__primarykey__ = "uid"
                tx.merge(a)
                graph.commit(tx)
            except Exception as exc:
                _handle_exception(exc, release)
    return project_items


def import_service_accounts(graph: Graph, collector, project_items, serviceaccount_list, release: bool) -> List:
    print("#### Service Account ####")

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("ServiceAccount").count()
    if existing_count > 0:
        print(
            f"⚠️ Database already has {existing_count} ServiceAccount nodes, skipping import."
        )
        return _safe_items(serviceaccount_list)

    if "all" not in collector and "sa" not in collector:
        return _safe_items(serviceaccount_list)

    service_accounts = _safe_items(serviceaccount_list)
    projects_by_name = {p.metadata.name: p for p in project_items}

    with _progress_bar("Service Account", service_accounts) as bar:
        if bar is None:
            return service_accounts
        for enum in service_accounts:
            namespace = enum.metadata.namespace
            try:
                tx = graph.begin()
                sa_node = Node(
                    "ServiceAccount",
                    name=enum.metadata.name,
                    namespace=namespace,
                    uid=enum.metadata.uid,
                )
                sa_node.__primarylabel__ = "ServiceAccount"
                sa_node.__primarykey__ = "uid"

                project = projects_by_name.get(namespace)
                if project:
                    project_node = Node(
                        "Project", name=project.metadata.name, uid=project.metadata.uid
                    )
                    project_node.__primarylabel__ = "Project"
                    project_node.__primarykey__ = "uid"
                else:
                    project_node = Node(
                        "AbsentProject", name=namespace, uid=namespace
                    )
                    project_node.__primarylabel__ = "AbsentProject"
                    project_node.__primarykey__ = "uid"

                relation = Relationship(project_node, "CONTAIN SA", sa_node)

                tx.merge(sa_node)
                tx.merge(project_node)
                tx.merge(relation)
                graph.commit(tx)
            except Exception as exc:
                _handle_exception(exc, release)
    return service_accounts


def import_scc(graph: Graph, collector, scc_list, release: bool) -> List:
    print("#### SCC ####")

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("SCC").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} SCC nodes, skipping import.")
        return _safe_items(scc_list)

    if "all" not in collector and "scc" not in collector:
        return _safe_items(scc_list)

    scc_items = _safe_items(scc_list)

    with _progress_bar("SCC", scc_items) as bar:
        if bar is None:
            return scc_items
        for scc in scc_items:
            try:
                tx = graph.begin()
                is_priv = scc.allowPrivilegedContainer
                scc_node = Node(
                    "SCC",
                    name=scc.metadata.name,
                    uid=scc.metadata.uid,
                    allowPrivilegeEscalation=is_priv,
                )
                scc_node.__primarylabel__ = "SCC"
                scc_node.__primarykey__ = "uid"
                tx.merge(scc_node)
                graph.commit(tx)
            except Exception as exc:
                _handle_exception(exc, release)
    return scc_items


def import_roles(graph: Graph, collector, role_list, scc_items, release: bool) -> List:
    print("#### Role ####")

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("Role").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} Role nodes, skipping import.")
        return _safe_items(role_list)

    if "all" not in collector and "role" not in collector:
        return _safe_items(role_list)

    roles = _safe_items(role_list)
    scc_by_name = {scc.metadata.name: scc for scc in scc_items}

    with _progress_bar("Role", roles) as bar:
        if bar is None:
            return roles
        for role in roles:
            role_node = Node(
                "Role",
                name=role.metadata.name,
                namespace=role.metadata.namespace,
                uid=role.metadata.uid,
            )
            role_node.__primarylabel__ = "Role"
            role_node.__primarykey__ = "uid"

            try:
                tx = graph.begin()
                tx.merge(role_node)
                graph.commit(tx)
            except Exception as exc:
                _handle_exception(exc, release)
                continue

            if not role.rules:
                continue

            for rule in role.rules:
                if rule.apiGroups:
                    for api_group in rule.apiGroups:
                        for resource in rule.resources or []:
                            if resource == "securitycontextconstraints":
                                if rule.resourceNames:
                                    for resource_name in rule.resourceNames:
                                        scc = scc_by_name.get(resource_name)
                                        if scc:
                                            scc_node = Node(
                                                "SCC",
                                                name=scc.metadata.name,
                                                uid=scc.metadata.uid,
                                            )
                                            scc_node.__primarylabel__ = "SCC"
                                            scc_node.__primarykey__ = "uid"
                                        else:
                                            scc_node = Node(
                                                "AbsentSCC",
                                                name=resource_name,
                                                uid="SCC_" + resource_name,
                                            )
                                            scc_node.__primarylabel__ = "AbsentSCC"
                                            scc_node.__primarykey__ = "uid"
                                        try:
                                            tx = graph.begin()
                                            rel = Relationship(role_node, "CAN USE SCC", scc_node)
                                            tx.merge(role_node)
                                            tx.merge(scc_node)
                                            tx.merge(rel)
                                            graph.commit(tx)
                                        except Exception as exc:
                                            _handle_exception(exc, release)
                            else:
                                for verb in rule.verbs or []:
                                    resource_name = resource
                                    if api_group:
                                        resource_name = f"{api_group}:{resource}"
                                    res_node = Node(
                                        "Resource",
                                        name=resource_name,
                                        uid="Resource_"
                                        + role.metadata.namespace
                                        + "_"
                                        + resource_name,
                                    )
                                    res_node.__primarylabel__ = "Resource"
                                    res_node.__primarykey__ = "uid"
                                    try:
                                        tx = graph.begin()
                                        relationship_type = "impers" if verb == "impersonate" else verb
                                        rel = Relationship(role_node, relationship_type, res_node)
                                        tx.merge(role_node)
                                        tx.merge(res_node)
                                        tx.merge(rel)
                                        graph.commit(tx)
                                    except Exception as exc:
                                        _handle_exception(exc, release)
                if getattr(rule, "nonResourceURLs", None):
                    for non_resource_url in rule.nonResourceURLs:
                        for verb in rule.verbs or []:
                            res_node = Node(
                                "ResourceNoUrl",
                                name=non_resource_url,
                                uid="ResourceNoUrl_"
                                + role.metadata.namespace
                                + "_"
                                + non_resource_url,
                            )
                            res_node.__primarylabel__ = "ResourceNoUrl"
                            res_node.__primarykey__ = "uid"
                            try:
                                tx = graph.begin()
                                rel = Relationship(role_node, verb, res_node)
                                tx.merge(role_node)
                                tx.merge(res_node)
                                tx.merge(rel)
                                graph.commit(tx)
                            except Exception as exc:
                                _handle_exception(exc, release)
    return roles


def import_clusterroles(graph: Graph, collector, clusterrole_list, scc_items, release: bool) -> List:
    print("#### ClusterRole ####")

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("ClusterRole").count()
    if existing_count > 0:
        print(
            f"⚠️ Database already has {existing_count} ClusterRole nodes, skipping import."
        )
        return _safe_items(clusterrole_list)

    if "all" not in collector and "clusterrole" not in collector:
        return _safe_items(clusterrole_list)

    clusterroles = _safe_items(clusterrole_list)
    scc_by_name = {scc.metadata.name: scc for scc in scc_items}

    with _progress_bar("ClusterRole", clusterroles) as bar:
        if bar is None:
            return clusterroles
        for role in clusterroles:
            try:
                tx = graph.begin()
                role_node = Node(
                    "ClusterRole", name=role.metadata.name, uid=role.metadata.uid
                )
                role_node.__primarylabel__ = "ClusterRole"
                role_node.__primarykey__ = "uid"
                tx.merge(role_node)
                graph.commit(tx)
            except Exception as exc:
                _handle_exception(exc, release)
                continue

            if not role.rules:
                continue

            for rule in role.rules:
                if rule.apiGroups:
                    for api_group in rule.apiGroups:
                        for resource in rule.resources or []:
                            if resource == "securitycontextconstraints":
                                if rule.resourceNames:
                                    for resource_name in rule.resourceNames:
                                        scc = scc_by_name.get(resource_name)
                                        if scc:
                                            scc_node = Node(
                                                "SCC",
                                                name=scc.metadata.name,
                                                uid=scc.metadata.uid,
                                            )
                                            scc_node.__primarylabel__ = "SCC"
                                            scc_node.__primarykey__ = "uid"
                                        else:
                                            scc_node = Node(
                                                "AbsentSCC",
                                                name=resource_name,
                                                uid="SCC_" + resource_name,
                                            )
                                            scc_node.__primarylabel__ = "AbsentSCC"
                                            scc_node.__primarykey__ = "uid"
                                        try:
                                            tx = graph.begin()
                                            rel = Relationship(role_node, "CAN USE SCC", scc_node)
                                            tx.merge(role_node)
                                            tx.merge(scc_node)
                                            tx.merge(rel)
                                            graph.commit(tx)
                                        except Exception as exc:
                                            _handle_exception(exc, release)
                            else:
                                for verb in rule.verbs or []:
                                    resource_name = resource
                                    if api_group:
                                        resource_name = f"{api_group}:{resource}"
                                    res_node = Node(
                                        "Resource",
                                        name=resource_name,
                                        uid="Resource_cluster" + "_" + resource_name,
                                    )
                                    res_node.__primarylabel__ = "Resource"
                                    res_node.__primarykey__ = "uid"
                                    try:
                                        tx = graph.begin()
                                        relationship_type = "impers" if verb == "impersonate" else verb
                                        rel = Relationship(role_node, relationship_type, res_node)
                                        tx.merge(role_node)
                                        tx.merge(res_node)
                                        tx.merge(rel)
                                        graph.commit(tx)
                                    except Exception as exc:
                                        _handle_exception(exc, release)
                if getattr(rule, "nonResourceURLs", None):
                    for non_resource_url in rule.nonResourceURLs:
                        for verb in rule.verbs or []:
                            res_node = Node(
                                "ResourceNoUrl",
                                name=non_resource_url,
                                uid="ResourceNoUrl_cluster" + "_" + non_resource_url,
                            )
                            res_node.__primarylabel__ = "ResourceNoUrl"
                            res_node.__primarykey__ = "uid"
                            try:
                                tx = graph.begin()
                                rel = Relationship(role_node, verb, res_node)
                                tx.merge(role_node)
                                tx.merge(res_node)
                                tx.merge(rel)
                                graph.commit(tx)
                            except Exception as exc:
                                _handle_exception(exc, release)
    return clusterroles


def import_users(graph: Graph, collector, user_list, release: bool) -> List:
    print("#### User ####")

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("User").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} User nodes, skipping import.")
        return _safe_items(user_list)

    if "all" not in collector and "user" not in collector:
        return _safe_items(user_list)

    users = _safe_items(user_list)

    with _progress_bar("User", users) as bar:
        if bar is None:
            return users
        for enum in users:
            name = enum.metadata.name
            uid = enum.metadata.uid
            user_node = Node("User", name=name, uid=uid)
            user_node.__primarylabel__ = "User"
            user_node.__primarykey__ = "uid"
            try:
                tx = graph.begin()
                tx.merge(user_node)
                graph.commit(tx)
            except Exception as exc:
                _handle_exception(exc, release)
    return users


def import_groups(graph: Graph, collector, group_list, user_items, release: bool) -> List:
    print("#### Group ####")

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("Group").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} Group nodes, skipping import.")
        return _safe_items(group_list)

    if "all" not in collector and "group" not in collector:
        return _safe_items(group_list)

    groups = _safe_items(group_list)
    users_by_name = {user.metadata.name: user for user in user_items}

    with _progress_bar("Group", groups) as bar:
        if bar is None:
            return groups
        for enum in groups:
            if not enum.users:
                continue
            for user in enum.users:
                group_node = Node("Group", name=enum.metadata.name, uid=enum.metadata.uid)
                group_node.__primarylabel__ = "Group"
                group_node.__primarykey__ = "uid"

                user_obj = users_by_name.get(user)
                if user_obj:
                    user_node = Node("User", name=user_obj.metadata.name, uid=user_obj.metadata.uid)
                    user_node.__primarylabel__ = "User"
                    user_node.__primarykey__ = "uid"
                else:
                    user_node = Node("AbsentUser", name=user, uid=user)
                    user_node.__primarylabel__ = "AbsentUser"
                    user_node.__primarykey__ = "uid"
                try:
                    tx = graph.begin()
                    rel = Relationship(group_node, "CONTAIN USER", user_node)
                    tx.merge(group_node)
                    tx.merge(user_node)
                    tx.merge(rel)
                    graph.commit(tx)
                except Exception as exc:
                    _handle_exception(exc, release)
    return groups


def _role_node_for_binding(role_kind, role_name, namespace, role_items, clusterrole_items):
    if role_kind == "ClusterRole":
        for role in clusterrole_items:
            if role.metadata.name == role_name:
                node = Node("ClusterRole", name=role.metadata.name, uid=role.metadata.uid)
                node.__primarylabel__ = "ClusterRole"
                node.__primarykey__ = "uid"
                return node
        node = Node("AbsentClusterRole", name=role_name, uid=role_name)
        node.__primarylabel__ = "AbsentClusterRole"
        node.__primarykey__ = "uid"
        return node

    if role_kind == "Role":
        for role in role_items:
            if role.metadata.name == role_name and role.metadata.namespace == namespace:
                node = Node(
                    "Role",
                    name=role.metadata.name,
                    namespace=role.metadata.namespace,
                    uid=role.metadata.uid,
                )
                node.__primarylabel__ = "Role"
                node.__primarykey__ = "uid"
                return node
        node = Node(
            "AbsentRole", name=role_name, namespace=namespace, uid=role_name + "_" + namespace
        )
        node.__primarylabel__ = "AbsentRole"
        node.__primarykey__ = "uid"
        return node

    return None


def _service_account_subject(subject_name, subject_namespace, project_items, service_account_items):
    project_node: Optional[Node]
    for project in project_items:
        if project.metadata.name == subject_namespace:
            project_node = Node("Project", name=project.metadata.name, uid=project.metadata.uid)
            project_node.__primarylabel__ = "Project"
            project_node.__primarykey__ = "uid"
            break
    else:
        project_node = Node("AbsentProject", name=subject_namespace, uid=subject_namespace)
        project_node.__primarylabel__ = "AbsentProject"
        project_node.__primarykey__ = "uid"

    for sa in service_account_items:
        if sa.metadata.name == subject_name and sa.metadata.namespace == subject_namespace:
            subject_node = Node(
                "ServiceAccount",
                name=sa.metadata.name,
                namespace=sa.metadata.namespace,
                uid=sa.metadata.uid,
            )
            subject_node.__primarylabel__ = "ServiceAccount"
            subject_node.__primarykey__ = "uid"
            break
    else:
        subject_node = Node(
            "AbsentServiceAccount",
            name=subject_name,
            namespace=subject_namespace,
            uid=subject_name + "_" + subject_namespace,
        )
        subject_node.__primarylabel__ = "AbsentServiceAccount"
        subject_node.__primarykey__ = "uid"

    return project_node, subject_node


def _group_subject(subject_name, project_items, group_items):
    if "system:serviceaccount:" in subject_name:
        parts = subject_name.split(":")
        group_namespace = parts[2]
        for project in project_items:
            if project.metadata.name == group_namespace:
                node = Node("Project", name=project.metadata.name, uid=project.metadata.uid)
                node.__primarylabel__ = "Project"
                node.__primarykey__ = "uid"
                return node
        node = Node("AbsentProject", name=group_namespace, uid=group_namespace)
        node.__primarylabel__ = "AbsentProject"
        node.__primarykey__ = "uid"
        return node

    if subject_name.startswith("system:"):
        node = Node("SystemGroup", name=subject_name, uid=subject_name)
        node.__primarylabel__ = "SystemGroup"
        node.__primarykey__ = "uid"
        return node

    for group in group_items:
        if group.metadata.name == subject_name:
            node = Node("Group", name=group.metadata.name, uid=group.metadata.uid)
            node.__primarylabel__ = "Group"
            node.__primarykey__ = "uid"
            return node

    node = Node("AbsentGroup", name=subject_name, uid=subject_name)
    node.__primarylabel__ = "AbsentGroup"
    node.__primarykey__ = "uid"
    return node


def _user_subject(subject_name, user_items):
    for user in user_items:
        if user.metadata.name == subject_name:
            node = Node("User", name=user.metadata.name, uid=user.metadata.uid)
            node.__primarylabel__ = "User"
            node.__primarykey__ = "uid"
            return node

    node = Node("AbsentUser", name=subject_name, uid=subject_name)
    node.__primarylabel__ = "AbsentUser"
    node.__primarykey__ = "uid"
    return node


def import_rolebindings(
    graph: Graph,
    collector,
    rolebinding_list,
    role_items,
    clusterrole_items,
    project_items,
    group_items,
    user_items,
    service_account_items,
    release: bool,
) -> List:
    print("#### RoleBinding ####")

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("RoleBinding").count()
    if existing_count > 0:
        print(
            f"⚠️ Database already has {existing_count} RoleBinding nodes, skipping import."
        )
        return _safe_items(rolebinding_list)

    if "all" not in collector and "rolebinding" not in collector:
        return _safe_items(rolebinding_list)

    rolebindings = _safe_items(rolebinding_list)

    with _progress_bar("RoleBinding", rolebindings) as bar:
        if bar is None:
            return rolebindings
        for enum in rolebindings:
            name = enum.metadata.name
            uid = enum.metadata.uid
            namespace = enum.metadata.namespace

            role_kind = enum.roleRef.kind
            role_name = enum.roleRef.name

            subjects_data = []
            if enum.subjects:
                for subject in enum.subjects:
                    raw_namespace = getattr(subject, "namespace", None)
                    effective_namespace = raw_namespace or namespace
                    subjects_data.append(
                        {
                            "kind": subject.kind,
                            "name": subject.name,
                            "namespace": raw_namespace,
                            "effective_namespace": effective_namespace,
                        }
                    )

            danger_reasons = assess_binding_risk(
                role_kind, role_name, subjects_data, "RoleBinding"
            )
            context_info = build_binding_context(
                role_kind, role_name, subjects_data, namespace, danger_reasons
            )
            danger_reasons_text = "; ".join(danger_reasons)

            rolebinding_node = Node(
                "RoleBinding",
                name=name,
                namespace=namespace,
                uid=uid,
                context=context_info,
                dangerous=bool(danger_reasons),
                danger_reasons=danger_reasons_text,
            )
            rolebinding_node.__primarylabel__ = "RoleBinding"
            rolebinding_node.__primarykey__ = "uid"

            role_node = _role_node_for_binding(
                role_kind, role_name, namespace, role_items, clusterrole_items
            )

            if subjects_data:
                for subject in subjects_data:
                    subject_kind = subject["kind"]
                    subject_name = subject["name"]
                    subject_namespace = subject.get("effective_namespace") or namespace

                    if subject_kind == "ServiceAccount":
                        project_node, subject_node = _service_account_subject(
                            subject_name, subject_namespace, project_items, service_account_items
                        )
                        try:
                            tx = graph.begin()
                            rel_project_sa = Relationship(project_node, "CONTAIN SA", subject_node)
                            rel_sa_binding = Relationship(subject_node, "HAS ROLEBINDING", rolebinding_node)
                            if role_kind == "ClusterRole":
                                rel_binding_role = Relationship(rolebinding_node, "HAS CLUSTERROLE", role_node)
                            elif role_kind == "Role":
                                rel_binding_role = Relationship(rolebinding_node, "HAS ROLE", role_node)
                            else:
                                rel_binding_role = None

                            tx.merge(project_node)
                            tx.merge(subject_node)
                            tx.merge(rolebinding_node)
                            if role_node:
                                tx.merge(role_node)
                            tx.merge(rel_project_sa)
                            tx.merge(rel_sa_binding)
                            if rel_binding_role is not None:
                                tx.merge(rel_binding_role)
                            graph.commit(tx)
                        except Exception as exc:
                            _handle_exception(exc, release)

                    elif subject_kind == "Group":
                        group_node = _group_subject(subject_name, project_items, group_items)
                        try:
                            tx = graph.begin()
                            rel_group_binding = Relationship(group_node, "HAS ROLEBINDING", rolebinding_node)
                            if role_kind == "ClusterRole":
                                rel_binding_role = Relationship(rolebinding_node, "HAS CLUSTERROLE", role_node)
                            elif role_kind == "Role":
                                rel_binding_role = Relationship(rolebinding_node, "HAS ROLE", role_node)
                            else:
                                rel_binding_role = None

                            tx.merge(group_node)
                            tx.merge(rolebinding_node)
                            if role_node:
                                tx.merge(role_node)
                            tx.merge(rel_group_binding)
                            if rel_binding_role is not None:
                                tx.merge(rel_binding_role)
                            graph.commit(tx)
                        except Exception as exc:
                            _handle_exception(exc, release)

                    elif subject_kind == "User":
                        user_node = _user_subject(subject_name, user_items)
                        try:
                            tx = graph.begin()
                            rel_user_binding = Relationship(user_node, "HAS ROLEBINDING", rolebinding_node)
                            if role_kind == "ClusterRole":
                                rel_binding_role = Relationship(rolebinding_node, "HAS CLUSTERROLE", role_node)
                            elif role_kind == "Role":
                                rel_binding_role = Relationship(rolebinding_node, "HAS ROLE", role_node)
                            else:
                                rel_binding_role = None

                            tx.merge(user_node)
                            tx.merge(rolebinding_node)
                            if role_node:
                                tx.merge(role_node)
                            tx.merge(rel_user_binding)
                            if rel_binding_role is not None:
                                tx.merge(rel_binding_role)
                            graph.commit(tx)
                        except Exception as exc:
                            _handle_exception(exc, release)

                    else:
                        print("[-] RoleBinding subjectKind not handled", subject_kind)

            else:
                try:
                    tx = graph.begin()
                    tx.merge(rolebinding_node)
                    if role_node:
                        tx.merge(role_node)
                    graph.commit(tx)
                except Exception as exc:
                    _handle_exception(exc, release)
    return rolebindings


def import_clusterrolebindings(
    graph: Graph,
    collector,
    clusterrolebinding_list,
    role_items,
    clusterrole_items,
    project_items,
    group_items,
    user_items,
    service_account_items,
    release: bool,
) -> List:
    print("#### ClusterRoleBinding ####")

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("ClusterRoleBinding").count()
    if existing_count > 0:
        print(
            f"⚠️ Database already has {existing_count} ClusterRoleBinding nodes, skipping import."
        )
        return _safe_items(clusterrolebinding_list)

    if "all" not in collector and "clusterrolebinding" not in collector:
        return _safe_items(clusterrolebinding_list)

    cluster_rolebindings = _safe_items(clusterrolebinding_list)

    with _progress_bar("ClusterRoleBinding", cluster_rolebindings) as bar:
        if bar is None:
            return cluster_rolebindings
        for enum in cluster_rolebindings:
            name = enum.metadata.name
            uid = enum.metadata.uid
            namespace = enum.metadata.namespace

            role_kind = enum.roleRef.kind
            role_name = enum.roleRef.name

            subjects_data = []
            if enum.subjects:
                for subject in enum.subjects:
                    raw_namespace = getattr(subject, "namespace", None)
                    effective_namespace = raw_namespace or namespace
                    subjects_data.append(
                        {
                            "kind": subject.kind,
                            "name": subject.name,
                            "namespace": raw_namespace,
                            "effective_namespace": effective_namespace,
                        }
                    )

            danger_reasons = assess_binding_risk(
                role_kind, role_name, subjects_data, "ClusterRoleBinding"
            )
            context_info = build_binding_context(
                role_kind, role_name, subjects_data, namespace, danger_reasons
            )
            danger_reasons_text = "; ".join(danger_reasons)

            cluster_rolebinding_node = Node(
                "ClusterRoleBinding",
                name=name,
                namespace=namespace,
                uid=uid,
                context=context_info,
                dangerous=bool(danger_reasons),
                danger_reasons=danger_reasons_text,
            )
            cluster_rolebinding_node.__primarylabel__ = "ClusterRoleBinding"
            cluster_rolebinding_node.__primarykey__ = "uid"

            role_node = _role_node_for_binding(
                role_kind, role_name, namespace, role_items, clusterrole_items
            )

            if subjects_data:
                for subject in subjects_data:
                    subject_kind = subject["kind"]
                    subject_name = subject["name"]
                    subject_namespace = subject.get("effective_namespace")

                    if subject_kind == "ServiceAccount":
                        project_node, subject_node = _service_account_subject(
                            subject_name,
                            subject_namespace,
                            project_items,
                            service_account_items,
                        )
                        try:
                            tx = graph.begin()
                            rel_project_sa = Relationship(project_node, "CONTAIN SA", subject_node)
                            rel_sa_binding = Relationship(
                                subject_node, "HAS CLUSTERROLEBINDING", cluster_rolebinding_node
                            )
                            if role_kind == "ClusterRole":
                                rel_binding_role = Relationship(
                                    cluster_rolebinding_node, "HAS CLUSTERROLE", role_node
                                )
                            elif role_kind == "Role":
                                rel_binding_role = Relationship(
                                    cluster_rolebinding_node, "HAS ROLE", role_node
                                )
                            else:
                                rel_binding_role = None

                            tx.merge(project_node)
                            tx.merge(subject_node)
                            tx.merge(cluster_rolebinding_node)
                            if role_node:
                                tx.merge(role_node)
                            tx.merge(rel_project_sa)
                            tx.merge(rel_sa_binding)
                            if rel_binding_role is not None:
                                tx.merge(rel_binding_role)
                            graph.commit(tx)
                        except Exception as exc:
                            _handle_exception(exc, release)

                    elif subject_kind == "Group":
                        group_node = _group_subject(subject_name, project_items, group_items)
                        try:
                            tx = graph.begin()
                            rel_group_binding = Relationship(
                                group_node, "HAS CLUSTERROLEBINDING", cluster_rolebinding_node
                            )
                            if role_kind == "ClusterRole":
                                rel_binding_role = Relationship(
                                    cluster_rolebinding_node, "HAS CLUSTERROLE", role_node
                                )
                            elif role_kind == "Role":
                                rel_binding_role = Relationship(
                                    cluster_rolebinding_node, "HAS ROLE", role_node
                                )
                            else:
                                rel_binding_role = None

                            tx.merge(group_node)
                            tx.merge(cluster_rolebinding_node)
                            if role_node:
                                tx.merge(role_node)
                            tx.merge(rel_group_binding)
                            if rel_binding_role is not None:
                                tx.merge(rel_binding_role)
                            graph.commit(tx)
                        except Exception as exc:
                            _handle_exception(exc, release)

                    elif subject_kind == "User":
                        user_node = _user_subject(subject_name, user_items)
                        try:
                            tx = graph.begin()
                            rel_user_binding = Relationship(
                                user_node, "HAS CLUSTERROLEBINDING", cluster_rolebinding_node
                            )
                            if role_kind == "ClusterRole":
                                rel_binding_role = Relationship(
                                    cluster_rolebinding_node, "HAS CLUSTERROLE", role_node
                                )
                            elif role_kind == "Role":
                                rel_binding_role = Relationship(
                                    cluster_rolebinding_node, "HAS ROLE", role_node
                                )
                            else:
                                rel_binding_role = None

                            tx.merge(user_node)
                            tx.merge(cluster_rolebinding_node)
                            if role_node:
                                tx.merge(role_node)
                            tx.merge(rel_user_binding)
                            if rel_binding_role is not None:
                                tx.merge(rel_binding_role)
                            graph.commit(tx)
                        except Exception as exc:
                            _handle_exception(exc, release)

                    else:
                        print("[-] RoleBinding subjectKind not handled", subject_kind)

            else:
                try:
                    tx = graph.begin()
                    tx.merge(cluster_rolebinding_node)
                    if role_node:
                        tx.merge(role_node)
                    graph.commit(tx)
                except Exception as exc:
                    _handle_exception(exc, release)
    return cluster_rolebindings


def import_routes(
    graph: Graph,
    collector,
    route_list,
    project_items,
    release: bool,
) -> List:
    print("#### Route ####")

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("Route").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} Route nodes, skipping import.")
        return _safe_items(route_list)

    if "all" not in collector and "route" not in collector:
        return _safe_items(route_list)

    routes = _safe_items(route_list)
    projects_by_name = {p.metadata.name: p for p in project_items}

    with _progress_bar("Route", routes) as bar:
        if bar is None:
            return routes
        for enum in routes:
            name = enum.metadata.name
            namespace = enum.metadata.namespace
            uid = enum.metadata.uid
            host = enum.spec.host
            path = enum.spec.path
            port = "any"
            if enum.spec.port:
                port = enum.spec.port.targetPort

            project = projects_by_name.get(namespace)
            if project:
                project_node = Node(
                    "Project", name=project.metadata.name, uid=project.metadata.uid
                )
                project_node.__primarylabel__ = "Project"
                project_node.__primarykey__ = "uid"
            else:
                project_node = Node("AbsentProject", name=namespace, uid=namespace)
                project_node.__primarylabel__ = "AbsentProject"
                project_node.__primarykey__ = "uid"

            route_node = Node(
                "Route",
                name=name,
                namespace=namespace,
                uid=uid,
                host=host,
                port=port,
                path=path,
            )
            route_node.__primarylabel__ = "Route"
            route_node.__primarykey__ = "uid"

            try:
                tx = graph.begin()
                relation = Relationship(project_node, "CONTAIN ROUTE", route_node)
                tx.merge(project_node)
                tx.merge(route_node)
                tx.merge(relation)
                graph.commit(tx)
            except Exception as exc:
                _handle_exception(exc, release)
    return routes


def import_pods(
    graph: Graph,
    collector,
    pod_list,
    project_items,
    release: bool,
) -> List:
    print("#### Pod ####")

    if "all" not in collector and "pod" not in collector:
        return _safe_items(pod_list)

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("Pod").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} Pod nodes, skipping import.")
        return _safe_items(pod_list)

    pods = _safe_items(pod_list)
    projects_by_name = {p.metadata.name: p for p in project_items}

    with _progress_bar("Pod", pods) as bar:
        if bar is None:
            return pods
        for enum in pods:
            name = enum.metadata.name
            namespace = enum.metadata.namespace
            uid = enum.metadata.uid

            project = projects_by_name.get(namespace)
            if project:
                project_node = Node(
                    "Project", name=project.metadata.name, uid=project.metadata.uid
                )
                project_node.__primarylabel__ = "Project"
                project_node.__primarykey__ = "uid"
            else:
                project_node = Node("AbsentProject", name=namespace)
                project_node.__primarylabel__ = "AbsentProject"
                project_node.__primarykey__ = "name"

            pod_node = Node("Pod", name=name, namespace=namespace, uid=uid)
            pod_node.__primarylabel__ = "Pod"
            pod_node.__primarykey__ = "uid"

            try:
                tx = graph.begin()
                relation = Relationship(project_node, "CONTAIN POD", pod_node)
                tx.merge(project_node)
                tx.merge(pod_node)
                tx.merge(relation)
                graph.commit(tx)
            except Exception as exc:
                _handle_exception(exc, release)
    return pods


def import_configmaps(
    graph: Graph,
    collector,
    configmap_list,
    project_items,
    release: bool,
) -> List:
    print("#### ConfigMap ####")

    if "all" not in collector and "configmap" not in collector:
        return _safe_items(configmap_list)

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("ConfigMap").count()
    if existing_count > 0:
        print(
            f"⚠️ Database already has {existing_count} ConfigMap nodes, skipping import."
        )
        return _safe_items(configmap_list)

    configmaps = _safe_items(configmap_list)
    projects_by_name = {p.metadata.name: p for p in project_items}

    with _progress_bar("ConfigMap", configmaps) as bar:
        if bar is None:
            return configmaps
        for enum in configmaps:
            name = enum.metadata.name
            namespace = enum.metadata.namespace
            uid = enum.metadata.uid

            project = projects_by_name.get(namespace)
            if project:
                project_node = Node(
                    "Project", name=project.metadata.name, uid=project.metadata.uid
                )
                project_node.__primarylabel__ = "Project"
                project_node.__primarykey__ = "uid"
            else:
                project_node = Node("AbsentProject", name=namespace)
                project_node.__primarylabel__ = "AbsentProject"
                project_node.__primarykey__ = "name"

            configmap_node = Node(
                "ConfigMap", name=name, namespace=namespace, uid=uid
            )
            configmap_node.__primarylabel__ = "ConfigMap"
            configmap_node.__primarykey__ = "uid"

            try:
                tx = graph.begin()
                relation = Relationship(project_node, "CONTAIN CONFIGMAP", configmap_node)
                tx.merge(project_node)
                tx.merge(configmap_node)
                tx.merge(relation)
                graph.commit(tx)
            except Exception as exc:
                _handle_exception(exc, release)
    return configmaps


def import_kyverno_whitelists(
    graph: Graph,
    collector,
    kyverno_logs: MutableMapping,
    project_items,
    service_account_items,
    release: bool,
) -> None:
    print("#### Kyverno whitelist ####")

    if "all" not in collector and "kyverno" not in collector:
        return

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("KyvernoWhitelist").count()
    if existing_count > 0:
        print(
            f"⚠️ Database already has {existing_count} KyvernoWhitelist nodes, skipping import."
        )
        return

    log_values = list(kyverno_logs.values())
    with _progress_bar("Kyverno", log_values) as bar:
        if bar is None:
            return
        for logs in log_values:
            try:
                excluded_username_list = re.search(
                    r"excludeUsernames=\[(.+?)\]", str(logs), re.IGNORECASE
                ).group(1)
                excluded_username_list = excluded_username_list.split(",")
            except Exception as err:
                print("\n[-] error excludeUsernames: " + str(err))
                continue

            for subject in excluded_username_list:
                subject = subject.replace('"', '')
                split = subject.split(":")

                if len(split) == 4 and split[1] == "serviceaccount":
                    subject_namespace = split[2]
                    subject_name = split[3]

                    project_node, subject_node = _service_account_subject(
                        subject_name, subject_namespace, project_items, service_account_items
                    )

                    try:
                        kyverno_whitelist_node = Node(
                            "KyvernoWhitelist",
                            name="KyvernoWhitelist",
                            uid="KyvernoWhitelist",
                        )
                        kyverno_whitelist_node.__primarylabel__ = "KyvernoWhitelist"
                        kyverno_whitelist_node.__primarykey__ = "uid"

                        tx = graph.begin()
                        rel_project_sa = Relationship(project_node, "CONTAIN SA", subject_node)
                        rel_sa_whitelist = Relationship(
                            subject_node, "CAN BYPASS KYVERNO", kyverno_whitelist_node
                        )

                        tx.merge(project_node)
                        tx.merge(subject_node)
                        tx.merge(kyverno_whitelist_node)
                        tx.merge(rel_project_sa)
                        tx.merge(rel_sa_whitelist)
                        graph.commit(tx)
                    except Exception as exc:
                        _handle_exception(exc, release)


def import_gatekeeper_whitelists(
    graph: Graph,
    collector,
    validatingwebhookconfiguration_list,
    release: bool,
) -> None:
    print("#### Gatekeeper whitelist ####")

    if "all" not in collector and "gatekeeper" not in collector:
        return

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("GatekeeperWhitelist").count()
    if existing_count > 0:
        print(
            f"⚠️ Database already has {existing_count} GatekeeperWhitelist nodes, skipping import."
        )
        return

    configs = _safe_items(validatingwebhookconfiguration_list)

    with _progress_bar("Gatekeeper", configs) as bar:
        if bar is None:
            return
        for enum in configs:
            name = enum.metadata.name

            if "gatekeeper-validating-webhook-configuration" not in name:
                continue

            webhooks = enum.webhooks
            if not webhooks:
                continue

            for webhook in enum.webhooks:
                webhook_name = webhook.name
                match_expressions = str(webhook.namespaceSelector.matchExpressions)
                try:
                    gatekeeper_node = Node(
                        "GatekeeperWhitelist",
                        name=webhook_name,
                        uid=webhook_name,
                        whitelist=match_expressions,
                    )
                    gatekeeper_node.__primarylabel__ = "GatekeeperWhitelist"
                    gatekeeper_node.__primarykey__ = "uid"

                    tx = graph.begin()
                    tx.merge(gatekeeper_node)
                    graph.commit(tx)
                except Exception as exc:
                    _handle_exception(exc, release)
