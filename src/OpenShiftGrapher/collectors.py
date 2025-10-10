"""Collector routines for OpenShiftGrapher."""

import os
import re
import sys
from dataclasses import dataclass

from py2neo import Node, Relationship
from progress.bar import Bar

SECTION_HEADERS = {
    "oauth": "#### OAuth ####",
    "identity": "#### Identities ####",
    "project": "#### Project ####",
    "service_account": "#### Service Account ####",
    "security_context_constraints": "#### SecurityContextConstraints ####",
    "role": "#### Role ####",
    "cluster_role": "#### ClusterRole ####",
    "user": "#### User ####",
    "group": "#### Group ####",
    "role_binding": "#### RoleBinding ####",
    "cluster_role_binding": "#### ClusterRoleBinding ####",
    "route": "#### Route ####",
    "pod": "#### Pod ####",
    "configmap": "#### ConfigMap ####",
    "kyverno": "#### Kyverno ####",
    "validating_webhook_configuration": "#### ValidatingWebhookConfiguration ####",
    "mutating_webhook_configuration": "#### MutatingWebhookConfiguration ####",
    "cluster_policy": "#### ClusterPolicy ####",
}

SECURITY_CONTEXT_CONSTRAINTS_LABEL = "SecurityContextConstraints"
ABSENT_SECURITY_CONTEXT_CONSTRAINTS_LABEL = "AbsentSecurityContextConstraints"
SECURITY_CONTEXT_CONSTRAINTS_BAR_LABEL = "SecurityContextConstraints"
SECURITY_CONTEXT_CONSTRAINTS_SKIP_MESSAGE = (
    "⚠️ SecurityContextConstraints graph up-to-date, skipping import."
)
REL_CAN_USE_SECURITY_CONTEXT_CONSTRAINTS = "CAN USE SecurityContextConstraints"
REL_CAN_USE_SECURITY_CONTEXT_CONSTRAINTS_UNDERSCORE = (
    "CAN_USE_SECURITY_CONTEXT_CONSTRAINTS"
)


def format_risk_tags(tags, default="✅ baseline"):
    """Return a human readable risk string while removing duplicates."""
    seen = set()
    ordered = []
    for tag in tags:
        if not tag:
            continue
        if tag not in seen:
            ordered.append(tag)
            seen.add(tag)
    return ", ".join(ordered) if ordered else default


@dataclass(slots=True)
class LookupTables:
    """Caches of Kubernetes objects keyed for fast lookups during collection."""

    project_by_name: dict
    serviceaccount_by_ns_name: dict
    security_context_constraints_by_name: dict
    role_by_ns_name: dict
    clusterrole_by_name: dict
    user_by_name: dict
    group_by_name: dict


@dataclass(slots=True)
class CollectorContext:
    """Shared state passed to the individual collector routines."""

    graph: object
    collector: set
    release: bool
    oauth_list: object
    identity_list: object
    project_list: object
    serviceAccount_list: object
    security_context_constraints_list: object
    role_list: object
    clusterrole_list: object
    user_list: object
    group_list: object
    roleBinding_list: object
    clusterRoleBinding_list: object
    route_list: object
    pod_list: object
    kyverno_logs: object
    configmap_list: object
    validatingWebhookConfiguration_list: object
    mutatingWebhookConfiguration_list: object
    clusterPolicy_list: object
    lookups: LookupTables

    @property
    def project_by_name(self):
        return self.lookups.project_by_name

    @property
    def serviceaccount_by_ns_name(self):
        return self.lookups.serviceaccount_by_ns_name

    @property
    def security_context_constraints_by_name(self):
        return self.lookups.security_context_constraints_by_name

    @property
    def role_by_ns_name(self):
        return self.lookups.role_by_ns_name

    @property
    def clusterrole_by_name(self):
        return self.lookups.clusterrole_by_name

    @property
    def user_by_name(self):
        return self.lookups.user_by_name

    @property
    def group_by_name(self):
        return self.lookups.group_by_name


def _should_collect(collector, *names):
    """Return True when the requested collectors include any of ``names``."""

    return "all" in collector or any(name in collector for name in names)


def _build_lookup_tables(
    project_list,
    serviceAccount_list,
    security_context_constraints_list,
    role_list,
    clusterrole_list,
    user_list,
    group_list,
):
    """Create lookup dictionaries used across multiple collector routines."""

    project_by_name = {}
    for item in getattr(project_list, "items", []) or []:
        metadata = getattr(item, "metadata", None)
        name = getattr(metadata, "name", None) if metadata else None
        if name:
            project_by_name[name] = item

    serviceaccount_by_ns_name = {}
    for item in getattr(serviceAccount_list, "items", []) or []:
        metadata = getattr(item, "metadata", None)
        namespace = getattr(metadata, "namespace", None) if metadata else None
        name = getattr(metadata, "name", None) if metadata else None
        if namespace and name:
            serviceaccount_by_ns_name[(namespace, name)] = item

    security_context_constraints_by_name = {}
    for item in getattr(security_context_constraints_list, "items", []) or []:
        metadata = getattr(item, "metadata", None)
        name = getattr(metadata, "name", None) if metadata else None
        if name:
            security_context_constraints_by_name[name] = item

    role_by_ns_name = {}
    for item in getattr(role_list, "items", []) or []:
        metadata = getattr(item, "metadata", None)
        namespace = getattr(metadata, "namespace", None) if metadata else None
        name = getattr(metadata, "name", None) if metadata else None
        if namespace and name:
            role_by_ns_name[(namespace, name)] = item

    clusterrole_by_name = {}
    for item in getattr(clusterrole_list, "items", []) or []:
        metadata = getattr(item, "metadata", None)
        name = getattr(metadata, "name", None) if metadata else None
        if name:
            clusterrole_by_name[name] = item

    user_by_name = {}
    for item in getattr(user_list, "items", []) or []:
        metadata = getattr(item, "metadata", None)
        name = getattr(metadata, "name", None) if metadata else None
        if name:
            user_by_name[name] = item

    group_by_name = {}
    for item in getattr(group_list, "items", []) or []:
        metadata = getattr(item, "metadata", None)
        name = getattr(metadata, "name", None) if metadata else None
        if name:
            group_by_name[name] = item

    return LookupTables(
        project_by_name=project_by_name,
        serviceaccount_by_ns_name=serviceaccount_by_ns_name,
        security_context_constraints_by_name=security_context_constraints_by_name,
        role_by_ns_name=role_by_ns_name,
        clusterrole_by_name=clusterrole_by_name,
        user_by_name=user_by_name,
        group_by_name=group_by_name,
    )


def run_collectors(
    graph,
    collector,
    release,
    oauth_list,
    identity_list,
    project_list,
    serviceAccount_list,
    security_context_constraints_list,
    role_list,
    clusterrole_list,
    user_list,
    group_list,
    roleBinding_list,
    clusterRoleBinding_list,
    route_list,
    pod_list,
    kyverno_logs,
    configmap_list,
    validatingWebhookConfiguration_list,
    mutatingWebhookConfiguration_list,
    clusterPolicy_list,
):
    collector = {item.lower() for item in (collector or [])}

    lookups = _build_lookup_tables(
        project_list,
        serviceAccount_list,
        security_context_constraints_list,
        role_list,
        clusterrole_list,
        user_list,
        group_list,
    )

    context = CollectorContext(
        graph=graph,
        collector=collector,
        release=release,
        oauth_list=oauth_list,
        identity_list=identity_list,
        project_list=project_list,
        serviceAccount_list=serviceAccount_list,
        security_context_constraints_list=security_context_constraints_list,
        role_list=role_list,
        clusterrole_list=clusterrole_list,
        user_list=user_list,
        group_list=group_list,
        roleBinding_list=roleBinding_list,
        clusterRoleBinding_list=clusterRoleBinding_list,
        route_list=route_list,
        pod_list=pod_list,
        kyverno_logs=kyverno_logs,
        configmap_list=configmap_list,
        validatingWebhookConfiguration_list=validatingWebhookConfiguration_list,
        mutatingWebhookConfiguration_list=mutatingWebhookConfiguration_list,
        clusterPolicy_list=clusterPolicy_list,
        lookups=lookups,
    )

    _collect_oauth(context)
    _collect_identities(context)
    _collect_project(context)
    _collect_service_account(context)
    _collect_securitycontextconstraints(context)
    _collect_role(context)
    _collect_clusterrole(context)
    _collect_user(context)
    _collect_group(context)
    _collect_rolebinding(context)
    _collect_clusterrolebinding(context)
    _collect_route(context)
    _collect_pod(context)
    _collect_configmap(context)
    _collect_kyverno(context)
    _collect_validatingwebhookconfiguration(context)
    _collect_mutatingwebhookconfiguration(context)
    _collect_clusterpolicy(context)


def _collect_oauth(ctx):
    """Collect OAuth resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## OAuth
    ##
    print(SECTION_HEADERS["oauth"])

    if _should_collect(collector, "oauth"):
        existing_count = graph.nodes.match("OAuth").count()
        if existing_count >= len(oauth_list.items):
            print(f"⚠️ Database already has {existing_count} OAuth nodes, skipping import.")
        else:
            with Bar('OAuth',max = len(oauth_list.items)) as bar:
                    for enum in oauth_list.items:
                        bar.next()

                        oauth_risk_tags = []
                        if not getattr(enum.spec, "identityProviders", []):
                            oauth_risk_tags.append("⚠️ no identity providers configured")

                        oauthNode = Node(
                            "OAuth",
                            name=enum.metadata.name,
                            risk=format_risk_tags(oauth_risk_tags)
                        )
                        oauthNode.__primarylabel__ = "OAuth"
                        oauthNode.__primarykey__ = "name"

                        tx = graph.begin()
                        tx.merge(oauthNode)

                        for idp in getattr(enum.spec, "identityProviders", []):
                            idp_risk_tags = []
                            provider_type = getattr(idp, "type", "").lower()
                            mapping_method = getattr(idp, "mappingMethod", "N/A")
                            if provider_type in {"basicauth", "htpasswd"}:
                                idp_risk_tags.append("⚠️ password-based IdP")
                            if mapping_method.lower() in {"add", "addloginprefix"}:
                                idp_risk_tags.append("⚠️ mapping allows duplicates")

                            idpNode = Node(
                                "IdentityProvider",
                                name=idp.name,
                                type=idp.type,
                                mappingMethod=mapping_method,
                                risk=format_risk_tags(idp_risk_tags)
                            )
                            idpNode.__primarylabel__ = "IdentityProvider"
                            idpNode.__primarykey__ = "name"
                            tx.merge(idpNode)

                            rel = Relationship(oauthNode, "USES_PROVIDER", idpNode)
                            tx.merge(rel)
                        graph.commit(tx)


def _collect_identities(ctx):
    """Collect Identities resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## Identities
    ##
    print(SECTION_HEADERS["identity"])

    if _should_collect(collector, "identity"):
        existing_count = graph.nodes.match("Identity").count()
        if existing_count >= len(identity_list.items):
            print(f"⚠️ Database already has {existing_count} Identity nodes, skipping import.")
        else:
            with Bar('Identities', max=len(identity_list.items)) as bar:
                for enum in identity_list.items:
                    bar.next()

                    name = getattr(enum.metadata, "name", "unknown")
                    provider_name = getattr(enum, "providerName", "unknown-provider")
                    provider_user = getattr(enum, "providerUserName", "unknown-user")
                    user_info = getattr(enum, "user", None)
                    linked_user = None
                    linked_user_uid = None

                    if user_info:
                        linked_user = getattr(user_info, "name", None)
                        linked_user_uid = getattr(user_info, "uid", None)

                    # ───────────────────────────────
                    # Identity node
                    # ───────────────────────────────
                    identity_risk_tags = []
                    if not linked_user:
                        identity_risk_tags.append("⚠️ not linked to a user")

                    if provider_name.lower().startswith("system:"):
                        identity_risk_tags.append("⚠️ system identity")

                    identityNode = Node(
                        "Identity",
                        name=name,
                        provider=provider_name,
                        providerUser=provider_user,
                        linkedUser=linked_user,
                        risk=format_risk_tags(identity_risk_tags)
                    )
                    identityNode.__primarylabel__ = "Identity"
                    identityNode.__primarykey__ = "name"

                    # ───────────────────────────────
                    # Related IdentityProvider node
                    # ───────────────────────────────
                    providerNode = Node(
                        "IdentityProvider",
                        name=provider_name
                    )
                    providerNode.__primarylabel__ = "IdentityProvider"
                    providerNode.__primarykey__ = "name"

                    # ───────────────────────────────
                    # Related User node (if linked)
                    # ───────────────────────────────
                    if linked_user:
                        userNode = Node(
                            "User",
                            name=linked_user,
                            uid=linked_user_uid
                        )
                        userNode.__primarylabel__ = "User"
                        userNode.__primarykey__ = "name"
                    else:
                        userNode = None

                    # ───────────────────────────────
                    # Write to Neo4j
                    # ───────────────────────────────
                    try:
                        tx = graph.begin()
                        tx.merge(identityNode)
                        tx.merge(providerNode)

                        rel1 = Relationship(identityNode, "FROM_PROVIDER", providerNode)
                        tx.merge(rel1)

                        if userNode:
                            tx.merge(userNode)
                            rel2 = Relationship(identityNode, "LINKED_TO_USER", userNode)
                            tx.merge(rel2)

                        graph.commit(tx)

                    except Exception as e:
                        if release:
                            print(e)
                            pass
                        else:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            print(exc_type, fname, exc_tb.tb_lineno)
                            print("Error:", e)
                            sys.exit(1)


def _collect_project(ctx):
    """Collect Project resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## Project
    ##
    print(SECTION_HEADERS["project"])    

    if _should_collect(collector, "project"):
        existing_count = graph.nodes.match("Project").count()
        if existing_count >= len(project_list.items):
            print(f"⚠️ Database already has {existing_count} Project nodes, skipping import.")
        else:
            with Bar('Project', max=len(project_list.items)) as bar:
                for enum in project_list.items:
                    bar.next()
                    try:
                        # ───────────────────────────────
                        # Basic project metadata
                        # ───────────────────────────────
                        name = getattr(enum.metadata, "name", "unknown")
                        uid = getattr(enum.metadata, "uid", name)
                        annotations = getattr(enum.metadata, "annotations", {}) or {}

                        display_name = annotations.get("openshift.io/display-name", None)
                        requester = annotations.get("openshift.io/requester", None)
                        description = annotations.get("openshift.io/description", None)
                        quota = annotations.get("openshift.io/quota", None)
                        managed_by = annotations.get("openshift.io/managed-by", None)
                        created = getattr(enum.metadata, "creationTimestamp", None)
                        phase = getattr(getattr(enum, "status", None), "phase", None)

                        # Classify if system project
                        isSystem = name.startswith("openshift") or name.startswith("kube-")

                        # ───────────────────────────────
                        # Determine risk markers
                        risk_tags = []
                        if isSystem:
                            risk_tags.append("⚠️ system namespace")
                        if requester is None:
                            risk_tags.append("⚠️ missing requester")
                        if phase and phase.lower() != "active":
                            risk_tags.append(f"⚠️ phase={phase}")

                        # Create Project node
                        # ───────────────────────────────
                        tx = graph.begin()
                        a = Node(
                            "Project",
                            name=name,
                            uid=uid,
                            displayName=display_name,
                            requester=requester,
                            description=description,
                            quota=quota,
                            managedBy=managed_by,
                            created=created,
                            phase=phase,
                            isSystem=isSystem,
                            annotations=str(annotations),  # keep full annotations dict as string
                            risk=format_risk_tags(risk_tags)
                        )
                        a.__primarylabel__ = "Project"
                        a.__primarykey__ = "uid"
                        tx.merge(a)
                        graph.commit(tx)

                    except Exception as e: 
                        if release:
                            print(e)
                            pass
                        else:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            print(exc_type, fname, exc_tb.tb_lineno)
                            print("Error:", e)
                            sys.exit(1)


def _collect_service_account(ctx):
    """Collect Service account resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## Service account
    ##
    print(SECTION_HEADERS["service_account"])

    if _should_collect(collector, "sa", "serviceaccount"):
        existing_count = graph.nodes.match("ServiceAccount").count()
        if existing_count >= len(serviceAccount_list.items):
            print(f"⚠️ Database already has {existing_count} ServiceAccount nodes, skipping import.")
        else:
            with Bar('Service Account',max = len(serviceAccount_list.items)) as bar:
                for enum in serviceAccount_list.items:
                    bar.next()
                    try:
                            # ───────────────────────────────
                        # Extract metadata
                        # ───────────────────────────────
                        name = getattr(enum.metadata, "name", None)
                        namespace = getattr(enum.metadata, "namespace", None)
                        uid = getattr(enum.metadata, "uid", f"{namespace}:{name}")

                        annotations = getattr(enum.metadata, "annotations", {}) or {}
                        labels = getattr(enum.metadata, "labels", {}) or {}
                        created = getattr(enum.metadata, "creationTimestamp", None)

                        secrets = [s.name for s in getattr(enum, "secrets", []) if hasattr(s, "name")]
                        imagePullSecrets = [s.name for s in getattr(enum, "imagePullSecrets", []) if hasattr(s, "name")]
                        automount = getattr(enum, "automountServiceAccountToken", None)

                        # ───────────────────────────────
                        # Determine risk markers
                        risk_tags = []
                        if automount is None or automount:
                            risk_tags.append("⚠️ token automount enabled")
                        if any("dockercfg" in secret for secret in secrets):
                            risk_tags.append("⚠️ legacy dockercfg secret")
                        if name == "default":
                            risk_tags.append("⚠️ default service account")
                        if namespace and namespace.startswith("openshift"):
                            risk_tags.append("⚠️ operates in system namespace")

                        # Create SA node
                        # ───────────────────────────────
                        tx = graph.begin()
                        a = Node(
                            "ServiceAccount",
                            name=name,
                            namespace=namespace,
                            uid=uid,
                            automount=automount,
                            secrets=",".join(secrets),
                            imagePullSecrets=",".join(imagePullSecrets),
                            created=created,
                            annotations=str(annotations),
                            labels=str(labels),
                            risk=format_risk_tags(risk_tags)
                        )
                        a.__primarylabel__ = "ServiceAccount"
                        a.__primarykey__ = "uid"

                        target_project = project_by_name.get(enum.metadata.namespace)

                        if target_project:
                            projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                            projectNode.__primarylabel__ = "Project"
                            projectNode.__primarykey__ = "uid"
                        else:
                            projectNode = Node("AbsentProject", name=enum.metadata.namespace, uid=enum.metadata.namespace)
                            projectNode.__primarylabel__ = "AbsentProject"
                            projectNode.__primarykey__ = "uid"

                        r2 = Relationship(projectNode, "CONTAIN SA", a)

                        node = tx.merge(a) 
                        node = tx.merge(projectNode) 
                        node = tx.merge(r2) 
                        graph.commit(tx)

                    except Exception as e: 
                        if release:
                            print(e)
                            pass
                        else:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            print(exc_type, fname, exc_tb.tb_lineno)
                            print("Error:", e)
                            sys.exit(1)


def _collect_securitycontextconstraints(ctx):
    """Collect SecurityContextConstraints resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## SecurityContextConstraints
    ##
    print(SECTION_HEADERS["security_context_constraints"])

    if _should_collect(collector, "scc", "securitycontextconstraints", "security_context_constraints"):
        existing_count = graph.nodes.match("SecurityContextConstraints").count()
        if existing_count >= len(security_context_constraints_list.items):
        #     print(SECURITY_CONTEXT_CONSTRAINTS_SKIP_MESSAGE)
        # else:
            with Bar(
                SECURITY_CONTEXT_CONSTRAINTS_BAR_LABEL,
                max=len(security_context_constraints_list.items)
            ) as bar:
                for scc in security_context_constraints_list.items:
                    bar.next()

                    try:
                        annotations = getattr(scc.metadata, "annotations", {}) or {}

                        isPriv = getattr(scc, "allowPrivilegedContainer", False)
                        risk_tags = []
                        if isPriv:
                            risk_tags.append("⚠️ allows privileged containers")
                        if getattr(scc, "allowHostNetwork", False):
                            risk_tags.append("⚠️ allows host network")
                        if getattr(scc, "allowHostPID", False):
                            risk_tags.append("⚠️ shares host PID")
                        if getattr(scc, "allowHostIPC", False):
                            risk_tags.append("⚠️ shares host IPC")

                        run_as_user = getattr(scc, "runAsUser", None)
                        if run_as_user and getattr(run_as_user, "type", "").lower() == "runasany":
                            risk_tags.append("⚠️ runAsUser=RunAsAny")

                        fs_group = getattr(scc, "fsGroup", None)
                        if fs_group and getattr(fs_group, "type", "").lower() == "runasany":
                            risk_tags.append("⚠️ fsGroup=RunAsAny")

                        se_linux = getattr(scc, "seLinuxContext", None)
                        if se_linux and getattr(se_linux, "type", "").lower() == "runasany":
                            risk_tags.append("⚠️ seLinux=RunAsAny")

                        tx = graph.begin()
                        security_context_constraints_node = Node(SECURITY_CONTEXT_CONSTRAINTS_LABEL, name=scc.metadata.name,
                            uid=scc.metadata.uid,
                            allowPrivilegeEscalation=getattr(scc, "allowPrivilegedContainer", None),
                            allowHostNetwork=getattr(scc, "allowHostNetwork", None),
                            allowHostPID=getattr(scc, "allowHostPID", None),
                            allowHostIPC=getattr(scc, "allowHostIPC", None),
                            priority=getattr(scc, "priority", None) if hasattr(scc, "priority") else None,
                            risk=format_risk_tags(risk_tags),
                            annotations=str(annotations)
                        )
                        security_context_constraints_node.__primarylabel__ = SECURITY_CONTEXT_CONSTRAINTS_LABEL
                        security_context_constraints_node.__primarykey__ = "uid"
                        node = tx.merge(security_context_constraints_node) 
                        graph.commit(tx)

                    except Exception as e: 
                        if release:
                            print(e)
                            pass
                        else:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            print(exc_type, fname, exc_tb.tb_lineno)
                            print("Error:", e)
                            sys.exit(1)

                    if hasattr(scc, "groups") and scc.groups:
                        for group in scc.groups:
                            try:

                                if group.startswith("system:"):
                                    # Special case for virtual groups
                                    groupNode = Node("SystemGroup",
                                        name=group,
                                        uid=group  # use the name as UID since it's unique
                                    )
                                    groupNode.__primarylabel__ = "SystemGroup"
                                    groupNode.__primarykey__ = "uid"

                                else:
                                    target_group = group_by_name.get(group)

                                    if target_group:
                                        groupNode = Node("Group", name=target_group.metadata.name, uid=target_group.metadata.uid)
                                        groupNode.__primarylabel__ = "Group"
                                        groupNode.__primarykey__ = "uid"
                                    else:
                                        groupNode = Node("AbsentGroup", name=group, uid=group)
                                        groupNode.__primarylabel__ = "AbsentGroup"
                                        groupNode.__primarykey__ = "uid"

                                # Create the SecurityContextConstraints -> Group relationship
                                tx = graph.begin()
                                r = Relationship(groupNode, REL_CAN_USE_SECURITY_CONTEXT_CONSTRAINTS, security_context_constraints_node)
                                tx.merge(groupNode)
                                tx.merge(security_context_constraints_node)
                                tx.merge(r)
                                graph.commit(tx)

                            except Exception as e:
                                if release:
                                    print(e)
                                    pass
                                else:
                                    exc_type, exc_obj, exc_tb = sys.exc_info()
                                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                                    print(exc_type, fname, exc_tb.tb_lineno)
                                    print("Error:", e)
                                    sys.exit(1)


                    if hasattr(scc, "users") and scc.users:
                        for subject in scc.users:
                            split = subject.split(":")
                            if len(split)==4:
                                if "serviceaccount" ==  split[1]:
                                    subjectNamespace = split[2]
                                    subjectName = split[3]

                                    if subjectNamespace:
                                        target_project = project_by_name.get(subjectNamespace)
                                        if target_project:
                                            projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                                            projectNode.__primarylabel__ = "Project"
                                            projectNode.__primarykey__ = "uid"
                                        else:
                                            projectNode = Node("AbsentProject", name=subjectNamespace, uid=subjectNamespace)
                                            projectNode.__primarylabel__ = "AbsentProject"
                                            projectNode.__primarykey__ = "uid"

                                        target_sa = serviceaccount_by_ns_name.get((subjectNamespace, subjectName))
                                        if target_sa:
                                            subjectNode = Node("ServiceAccount",name=target_sa.metadata.name, namespace=target_sa.metadata.namespace, uid=target_sa.metadata.uid)
                                            subjectNode.__primarylabel__ = "ServiceAccount"
                                            subjectNode.__primarykey__ = "uid"
                                        else:
                                            subjectNode = Node("AbsentServiceAccount", name=subjectName, namespace=subjectNamespace, uid=subjectName+"_"+subjectNamespace)
                                            subjectNode.__primarylabel__ = "AbsentServiceAccount"
                                            subjectNode.__primarykey__ = "uid"

                                        try:
                                            tx = graph.begin()
                                            r1 = Relationship(projectNode, "CONTAIN SA", subjectNode)
                                            r2 = Relationship(subjectNode, REL_CAN_USE_SECURITY_CONTEXT_CONSTRAINTS, security_context_constraints_node)
                                            node = tx.merge(projectNode) 
                                            node = tx.merge(subjectNode) 
                                            node = tx.merge(security_context_constraints_node) 
                                            node = tx.merge(r1) 
                                            node = tx.merge(r2) 
                                            graph.commit(tx)

                                        except Exception as e: 
                                            if release:
                                                print(e)
                                                pass
                                            else:
                                                exc_type, exc_obj, exc_tb = sys.exc_info()
                                                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                                                print(exc_type, fname, exc_tb.tb_lineno)
                                                print("Error:", e)
                                                sys.exit(1)


def _collect_role(ctx):
    """Collect Role resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## Role
    ## 
    print(SECTION_HEADERS["role"])

    if _should_collect(collector, "role"):
        existing_count = graph.nodes.match("Role").count()
        if existing_count >= len(role_list.items):
            print(f"⚠️ Database already has {existing_count} Role nodes, skipping import.")
        else:
            with Bar('Role', max=len(role_list.items)) as bar:
                batch = 0
                tx = graph.begin()

                for role in role_list.items:
                    bar.next()
                    try:
                        # ───────────────────────────────
                        # Metadata extraction
                        # ───────────────────────────────
                        name = getattr(role.metadata, "name", "unknown")
                        namespace = getattr(role.metadata, "namespace", "unknown")
                        uid = getattr(role.metadata, "uid", f"{namespace}:{name}")
                        annotations = getattr(role.metadata, "annotations", {}) or {}
                        labels = getattr(role.metadata, "labels", {}) or {}
                        created = getattr(role.metadata, "creationTimestamp", None)

                        # ───────────────────────────────
                        # Detect privilege escalation
                        # ───────────────────────────────
                        dangerous_verbs = {"create", "update", "patch", "delete", "*", "impersonate", "bind"}
                        risk_tags = []

                        for rule in getattr(role, "rules", []) or []:
                            verbs = getattr(rule, "verbs", []) or []
                            resources = getattr(rule, "resources", []) or []
                            api_groups = getattr(rule, "apiGroups", []) or []
                            if "*" in verbs:
                                risk_tags.append("⚠️ wildcard verbs")
                            if "*" in resources:
                                risk_tags.append("⚠️ wildcard resources")
                            if "*" in api_groups:
                                risk_tags.append("⚠️ wildcard API groups")

                            for verb in verbs:
                                for resource in resources:
                                    if resource in {"secrets", "configmaps"} and verb in dangerous_verbs:
                                        risk_tags.append("⚠️ can modify secrets/configmaps")
                                    if resource == "serviceaccounts" and verb in dangerous_verbs:
                                        risk_tags.append("⚠️ can modify serviceaccounts")
                                    if resource == "securitycontextconstraints" and verb.lower() in {"use", "*"}:
                                        risk_tags.append("⚠️ can use SecurityContextConstraints")
                                    if resource.startswith("pods/") and verb in dangerous_verbs:
                                        risk_tags.append("⚠️ pod exec/attach rights")

                        # ───────────────────────────────
                        # Create Role node
                        # ───────────────────────────────
                        roleNode = Node(
                            "Role",
                            name=name,
                            namespace=namespace,
                            uid=uid,
                            created=created,
                            annotations=str(annotations),
                            labels=str(labels),
                            risk=format_risk_tags(risk_tags, default="✅ normal")
                        )
                        roleNode.__primarylabel__ = "Role"
                        roleNode.__primarykey__ = "uid"
                        tx.merge(roleNode)

                        # ───────────────────────────────
                        # Link Role → Project
                        # ───────────────────────────────
                        target_project = project_by_name.get(namespace)
                        if target_project:
                            projectNode = Node("Project",
                                            name=target_project.metadata.name,
                                            uid=target_project.metadata.uid)
                            projectNode.__primarylabel__ = "Project"
                            projectNode.__primarykey__ = "uid"
                        else:
                            projectNode = Node("AbsentProject", name=namespace, uid=namespace)
                            projectNode.__primarylabel__ = "AbsentProject"
                            projectNode.__primarykey__ = "uid"

                        tx.merge(projectNode)
                        tx.merge(Relationship(projectNode, "CONTAINS_ROLE", roleNode))

                        # ───────────────────────────────
                        # Rules → Resource relationships
                        # ───────────────────────────────
                        for rule in getattr(role, "rules", []) or []:
                            apiGroups = getattr(rule, "apiGroups", []) or []
                            resources = getattr(rule, "resources", []) or []
                            verbs = getattr(rule, "verbs", []) or []
                            nonResourceURLs = getattr(rule, "nonResourceURLs", []) or []

                            # Handle SecurityContextConstraints explicitly
                            for apiGroup in apiGroups:
                                for resource in resources:
                                    if resource == "securitycontextconstraints":
                                        for resourceName in getattr(rule, "resourceNames", []) or []:
                                            target_scc = security_context_constraints_by_name.get(resourceName)
                                            if target_scc:
                                                security_context_constraints_node = Node(SECURITY_CONTEXT_CONSTRAINTS_LABEL, 
                                                            name=target_scc.metadata.name,
                                                            uid=target_scc.metadata.uid,
                                                            exists=True)
                                            else:
                                                security_context_constraints_node = Node(ABSENT_SECURITY_CONTEXT_CONSTRAINTS_LABEL, 
                                                            name=resourceName,
                                                            uid=f"SecurityContextConstraints_{resourceName}",
                                                            exists=False)

                                            security_context_constraints_node.__primarylabel__ = SECURITY_CONTEXT_CONSTRAINTS_LABEL
                                            security_context_constraints_node.__primarykey__ = "uid"
                                            tx.merge(security_context_constraints_node)
                                            tx.merge(Relationship(roleNode, REL_CAN_USE_SECURITY_CONTEXT_CONSTRAINTS_UNDERSCORE, security_context_constraints_node))

                                    else:
                                        for verb in verbs:
                                            verb_safe = re.sub(r'[^a-zA-Z0-9_]', '_', verb)
                                            resourceName = f"{apiGroup}:{resource}" if apiGroup else resource

                                            resNode = Node("Resource",
                                                        name=resourceName,
                                                        uid=f"Resource_{namespace}_{resourceName}")
                                            resNode.__primarylabel__ = "Resource"
                                            resNode.__primarykey__ = "uid"
                                            tx.merge(resNode)

                                            tx.merge(Relationship(roleNode, verb_safe, resNode))

                            # Handle nonResourceURLs
                            for nonResourceURL in nonResourceURLs:
                                for verb in verbs:
                                    verb_safe = re.sub(r'[^a-zA-Z0-9_]', '_', verb)
                                    resNode = Node("ResourceNoUrl",
                                                name=nonResourceURL,
                                                uid=f"ResourceNoUrl_{namespace}_{nonResourceURL}")
                                    resNode.__primarylabel__ = "ResourceNoUrl"
                                    resNode.__primarykey__ = "uid"
                                    tx.merge(resNode)

                                    tx.merge(Relationship(roleNode, verb_safe, resNode))

                        # ───────────────────────────────
                        # Batch commit every 100 roles
                        # ───────────────────────────────
                        batch += 1
                        if batch % 100 == 0:
                            graph.commit(tx)
                            tx = graph.begin()

                    except Exception as e:
                        if release:
                            print(e)
                            pass
                        else:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            print(exc_type, fname, exc_tb.tb_lineno)
                            print("Error:", e)
                            sys.exit(1)

                # Final commit
                graph.commit(tx)


def _collect_clusterrole(ctx):
    """Collect ClusterRole resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## ClusterRole
    ## 
    print(SECTION_HEADERS["cluster_role"])

    if _should_collect(collector, "clusterrole"):
        existing_count = graph.nodes.match("ClusterRole").count()
        if existing_count >= len(clusterrole_list.items):
            print(f"⚠️ Database already has {existing_count} ClusterRole nodes, skipping import.")
        else:
            with Bar('ClusterRole', max=len(clusterrole_list.items)) as bar:
                batch = 0
                tx = graph.begin()

                for role in clusterrole_list.items:
                    bar.next()
                    try:
                        # ───────────────────────────────
                        # Metadata extraction
                        # ───────────────────────────────
                        name = getattr(role.metadata, "name", "unknown")
                        uid = getattr(role.metadata, "uid", name)
                        annotations = getattr(role.metadata, "annotations", {}) or {}
                        labels = getattr(role.metadata, "labels", {}) or {}
                        created = getattr(role.metadata, "creationTimestamp", None)

                        # ───────────────────────────────
                        # Privilege escalation detection
                        # ───────────────────────────────
                        dangerous_verbs = {"create", "update", "patch", "delete", "*", "impersonate", "bind"}
                        risk_tags = []

                        aggregation_rule = getattr(role, "aggregationRule", None)
                        if aggregation_rule and getattr(aggregation_rule, "clusterRoleSelectors", None):
                            risk_tags.append("⚠️ aggregated cluster role")

                        for rule in getattr(role, "rules", []) or []:
                            verbs = getattr(rule, "verbs", []) or []
                            resources = getattr(rule, "resources", []) or []
                            api_groups = getattr(rule, "apiGroups", []) or []
                            if "*" in verbs:
                                risk_tags.append("⚠️ wildcard verbs")
                            if "*" in resources:
                                risk_tags.append("⚠️ wildcard resources")
                            if "*" in api_groups:
                                risk_tags.append("⚠️ wildcard API groups")

                            for verb in verbs:
                                for resource in resources:
                                    if resource in {"secrets", "configmaps"} and verb in dangerous_verbs:
                                        risk_tags.append("⚠️ can modify secrets/configmaps")
                                    if resource == "serviceaccounts" and verb in dangerous_verbs:
                                        risk_tags.append("⚠️ can modify serviceaccounts")
                                    if resource == "securitycontextconstraints" and verb.lower() in {"use", "*"}:
                                        risk_tags.append("⚠️ can use SecurityContextConstraints")
                                    if resource.startswith("pods/") and verb in dangerous_verbs:
                                        risk_tags.append("⚠️ pod exec/attach rights")

                        # ───────────────────────────────
                        # Create ClusterRole node
                        # ───────────────────────────────
                        roleNode = Node(
                            "ClusterRole",
                            name=name,
                            uid=uid,
                            created=created,
                            annotations=str(annotations),
                            labels=str(labels),
                            risk=format_risk_tags(risk_tags, default="✅ normal")
                        )
                        roleNode.__primarylabel__ = "ClusterRole"
                        roleNode.__primarykey__ = "uid"
                        tx.merge(roleNode)

                        # ───────────────────────────────
                        # Rules → Resource relationships
                        # ───────────────────────────────
                        for rule in getattr(role, "rules", []) or []:
                            apiGroups = getattr(rule, "apiGroups", []) or []
                            resources = getattr(rule, "resources", []) or []
                            verbs = getattr(rule, "verbs", []) or []
                            nonResourceURLs = getattr(rule, "nonResourceURLs", []) or []

                            # Handle SecurityContextConstraints explicitly
                            for apiGroup in apiGroups:
                                for resource in resources:
                                    if resource == "securitycontextconstraints":
                                        for resourceName in getattr(rule, "resourceNames", []) or []:
                                            target_scc = security_context_constraints_by_name.get(resourceName)
                                            if target_scc:
                                                security_context_constraints_node = Node(
                                                    SECURITY_CONTEXT_CONSTRAINTS_LABEL,
                                                    name=target_scc.metadata.name,
                                                    uid=target_scc.metadata.uid,
                                                    exists=True
                                                )
                                            else:
                                                security_context_constraints_node = Node(
                                                    ABSENT_SECURITY_CONTEXT_CONSTRAINTS_LABEL,
                                                    name=resourceName,
                                                    uid=f"SecurityContextConstraints_{resourceName}",
                                                    exists=False
                                                )

                                            security_context_constraints_node.__primarylabel__ = SECURITY_CONTEXT_CONSTRAINTS_LABEL
                                            security_context_constraints_node.__primarykey__ = "uid"
                                            tx.merge(security_context_constraints_node)
                                            tx.merge(Relationship(roleNode, REL_CAN_USE_SECURITY_CONTEXT_CONSTRAINTS_UNDERSCORE, security_context_constraints_node))

                                    else:
                                        for verb in verbs:
                                            verb_safe = re.sub(r'[^a-zA-Z0-9_]', '_', verb)
                                            resourceName = f"{apiGroup}:{resource}" if apiGroup else resource

                                            resNode = Node(
                                                "Resource",
                                                name=resourceName,
                                                uid=f"Resource_cluster_{resourceName}"
                                            )
                                            resNode.__primarylabel__ = "Resource"
                                            resNode.__primarykey__ = "uid"
                                            tx.merge(resNode)

                                            tx.merge(Relationship(roleNode, verb_safe, resNode))

                            # Handle nonResourceURLs
                            for nonResourceURL in nonResourceURLs:
                                for verb in verbs:
                                    verb_safe = re.sub(r'[^a-zA-Z0-9_]', '_', verb)
                                    resNode = Node(
                                        "ResourceNoUrl",
                                        name=nonResourceURL,
                                        uid=f"ResourceNoUrl_cluster_{nonResourceURL}"
                                    )
                                    resNode.__primarylabel__ = "ResourceNoUrl"
                                    resNode.__primarykey__ = "uid"
                                    tx.merge(resNode)
                                    tx.merge(Relationship(roleNode, verb_safe, resNode))

                        # ───────────────────────────────
                        # Batch commit every 100 roles
                        # ───────────────────────────────
                        batch += 1
                        if batch % 100 == 0:
                            graph.commit(tx)
                            tx = graph.begin()

                    except Exception as e:
                        if release:
                            print(e)
                            pass
                        else:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            print(exc_type, fname, exc_tb.tb_lineno)
                            print("Error:", e)
                            sys.exit(1)

                # Final commit
                graph.commit(tx)


def _collect_user(ctx):
    """Collect User resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## User
    ## 
    print(SECTION_HEADERS["user"])

    if _should_collect(collector, "user"):
        # Users are already imported via Identity, but we need to access the risks
        if True:
        # existing_count = graph.nodes.match("User").count()
        # if existing_count >= len(user_list.items):
        #     print(f"⚠️ Database already has {existing_count} User nodes, skipping import.")
        # else:
            with Bar('User', max=len(user_list.items)) as bar:
                batch = 0
                tx = graph.begin()

                for enum in user_list.items:
                    bar.next()
                    try:
                        # ───────────────────────────────
                        # Metadata extraction
                        # ───────────────────────────────
                        name = getattr(enum.metadata, "name", "unknown")
                        uid = getattr(enum.metadata, "uid", name)
                        annotations = getattr(enum.metadata, "annotations", {}) or {}
                        labels = getattr(enum.metadata, "labels", {}) or {}
                        created = getattr(enum.metadata, "creationTimestamp", None)
                        identities = getattr(enum, "identities", []) or []

                        # ───────────────────────────────
                        # Risk detection
                        # ───────────────────────────────
                        user_risk_tags = []
                        if name.startswith("system:"):
                            user_risk_tags.append("⚠️ system account")
                        if name in ["kube:admin", "admin", "system:admin"]:
                            user_risk_tags.append("⚠️ cluster administrator")
                        if not identities:
                            user_risk_tags.append("⚠️ no linked identities")

                        # ───────────────────────────────
                        # Create User node
                        # ───────────────────────────────
                        userNode = Node(
                            "User",
                            name=name,
                            uid=uid,
                            created=created,
                            annotations=str(annotations),
                            labels=str(labels),
                            risk=format_risk_tags(user_risk_tags, default="✅ normal")
                        )
                        userNode.__primarylabel__ = "User"
                        userNode.__primarykey__ = "uid"
                        tx.merge(userNode)

                        # # ───────────────────────────────
                        # # Link User → Identity nodes
                        # # ───────────────────────────────
                        # for identity_ref in identities:
                        #     # Example identity_ref: "github:john", "ldap:uid=jdoe,ou=users"
                        #     provider, sep, id_name = identity_ref.partition(":")
                        #     idNode = Node(
                        #         "Identity",
                        #         name=id_name if id_name else identity_ref,
                        #         provider=provider if sep else "unknown",
                        #         uid=f"Identity_{identity_ref}"
                        #     )
                        #     idNode.__primarylabel__ = "Identity"
                        #     idNode.__primarykey__ = "uid"

                        #     tx.merge(idNode)
                        #     tx.merge(Relationship(userNode, "LINKED_TO_IDENTITY", idNode))

                        # ───────────────────────────────
                        # Batch commit every 100 users
                        # ───────────────────────────────
                        batch += 1
                        if batch % 100 == 0:
                            graph.commit(tx)
                            tx = graph.begin()

                    except Exception as e:
                        if release:
                            print(e)
                            pass
                        else:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            print(exc_type, fname, exc_tb.tb_lineno)
                            print("Error:", e)
                            sys.exit(1)

                # Final commit
                graph.commit(tx)


def _collect_group(ctx):
    """Collect Group resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## Group
    ## 
    print(SECTION_HEADERS["group"])

    if _should_collect(collector, "group"):
        existing_count = graph.nodes.match("Group").count()
        if existing_count >= len(group_list.items):
            print(f"⚠️ Database already has {existing_count} Group nodes, skipping import.")
        else:
            with Bar('Group', max=len(group_list.items)) as bar:
                batch = 0
                tx = graph.begin()

                for enum in group_list.items:
                    bar.next()
                    try:
                        # ───────────────────────────────
                        # Metadata extraction
                        # ───────────────────────────────
                        name = getattr(enum.metadata, "name", "unknown")
                        uid = getattr(enum.metadata, "uid", name)
                        annotations = getattr(enum.metadata, "annotations", {}) or {}
                        labels = getattr(enum.metadata, "labels", {}) or {}
                        created = getattr(enum.metadata, "creationTimestamp", None)
                        users = getattr(enum, "users", []) or []

                        # ───────────────────────────────
                        # Risk detection
                        # ───────────────────────────────
                        group_risk_tags = []
                        if name.startswith("system:authenticated"):
                            group_risk_tags.append("⚠️ all authenticated users")
                        if name.startswith("system:unauthenticated"):
                            group_risk_tags.append("⚠️ unauthenticated group")
                        if name.startswith("system:") and not group_risk_tags:
                            group_risk_tags.append("⚠️ system group")
                        if not users:
                            group_risk_tags.append("⚠️ no direct members")

                        # ───────────────────────────────
                        # Create Group node
                        # ───────────────────────────────
                        groupNode = Node(
                            "Group",
                            name=name,
                            uid=uid,
                            created=created,
                            annotations=str(annotations),
                            labels=str(labels),
                            risk=format_risk_tags(group_risk_tags, default="✅ normal")
                        )
                        groupNode.__primarylabel__ = "Group"
                        groupNode.__primarykey__ = "uid"
                        tx.merge(groupNode)

                        # ───────────────────────────────
                        # Link Group → Users
                        # ───────────────────────────────
                        for user_name in users:
                            target_user = user_by_name.get(user_name)
                            if target_user:
                                userNode = Node(
                                    "User",
                                    name=target_user.metadata.name,
                                    uid=target_user.metadata.uid
                                )
                            else:
                                userNode = Node(
                                    "AbsentUser",
                                    name=user_name,
                                    uid=user_name
                                )

                            userNode.__primarylabel__ = "User"
                            userNode.__primarykey__ = "uid"
                            tx.merge(userNode)

                            rel = Relationship(groupNode, "CONTAINS_USER", userNode)
                            tx.merge(rel)

                        # ───────────────────────────────
                        # Batch commit every 100 groups
                        # ───────────────────────────────
                        batch += 1
                        if batch % 100 == 0:
                            graph.commit(tx)
                            tx = graph.begin()

                    except Exception as e:
                        if release:
                            print(e)
                            pass
                        else:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            print(exc_type, fname, exc_tb.tb_lineno)
                            print("Error:", e)
                            sys.exit(1)

                # Final commit
                graph.commit(tx)


def _collect_rolebinding(ctx):
    """Collect RoleBinding resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## RoleBinding
    ## 
    print(SECTION_HEADERS["role_binding"])

    if _should_collect(collector, "rolebinding"):
        existing_count = graph.nodes.match("RoleBinding").count()
        if existing_count >= len(roleBinding_list.items):
            print(f"⚠️ Database already has {existing_count} RoleBinding nodes, skipping import.")
        else:
            with Bar('RoleBinding',max = len(roleBinding_list.items)) as bar:

                for enum in roleBinding_list.items:
                    bar.next()

                    # print(enum)
                    name = enum.metadata.name
                    uid = enum.metadata.uid
                    namespace = enum.metadata.namespace

                    roleKind = enum.roleRef.kind
                    roleName = enum.roleRef.name
                    subjects = list(enum.subjects or [])

                    risk_tags = []
                    high_priv_roles = {"cluster-admin", "system:masters", "system:admin"}
                    if roleKind == "ClusterRole" and roleName in high_priv_roles:
                        risk_tags.append("⚠️ grants cluster-admin access")
                    if not subjects:
                        risk_tags.append("⚠️ no subjects bound")

                    for subject in subjects:
                        subjectKind = getattr(subject, "kind", "")
                        subjectName = getattr(subject, "name", "")
                        if subjectKind == "Group" and subjectName in {"system:authenticated", "system:unauthenticated"}:
                            risk_tags.append(f"⚠️ binds {subjectName}")
                        if subjectKind == "ServiceAccount" and subjectName == "default":
                            risk_tags.append("⚠️ default service account escalation")

                    rolebindingNode = Node(
                        "RoleBinding",
                        name=name,
                        namespace=namespace,
                        uid=enum.metadata.uid,
                        risk=format_risk_tags(risk_tags, default="✅ normal")
                    )
                    rolebindingNode.__primarylabel__ = "RoleBinding"
                    rolebindingNode.__primarykey__ = "uid"

                    if roleKind == "ClusterRole":
                        target_clusterroles = clusterrole_by_name.get(roleName)
                        if target_clusterroles:
                            roleNode = Node("ClusterRole",name=target_clusterroles.metadata.name, uid=target_clusterroles.metadata.uid)
                            roleNode.__primarylabel__ = "ClusterRole"
                            roleNode.__primarykey__ = "uid"

                        else:
                            roleNode = Node("AbsentClusterRole", name=roleName, uid=roleName)
                            roleNode.__primarylabel__ = "AbsentClusterRole"
                            roleNode.__primarykey__ = "uid"

                    elif roleKind == "Role":
                        target_role = role_by_ns_name.get((enum.metadata.namespace, roleName))
                        if target_role:
                            roleNode = Node("Role",name=target_role.metadata.name, namespace=target_role.metadata.namespace, uid=target_role.metadata.uid)
                            roleNode.__primarylabel__ = "Role"
                            roleNode.__primarykey__ = "uid"

                        else:
                            roleNode = Node("AbsentRole",name=roleName, namespace=namespace, uid=roleName + "_" + namespace)
                            roleNode.__primarylabel__ = "AbsentRole"
                            roleNode.__primarykey__ = "uid"

                    if subjects:
                        for subject in subjects:
                            subjectKind = subject.kind
                            subjectName = subject.name
                            subjectNamespace = subject.namespace

                            if not subjectNamespace:
                                subjectNamespace = namespace

                            if subjectKind == "ServiceAccount": 
                                if subjectNamespace:
                                    target_project = project_by_name.get(subjectNamespace)
                                    if target_project:
                                        projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                                        projectNode.__primarylabel__ = "Project"
                                        projectNode.__primarykey__ = "uid"
                                    else:
                                        projectNode = Node("AbsentProject", name=subjectNamespace, uid=subjectNamespace)
                                        projectNode.__primarylabel__ = "AbsentProject"
                                        projectNode.__primarykey__ = "uid"

                                    target_sa = serviceaccount_by_ns_name.get((subjectNamespace, subjectName))
                                    if target_sa:
                                        subjectNode = Node("ServiceAccount",name=target_sa.metadata.name, namespace=target_sa.metadata.namespace, uid=target_sa.metadata.uid)
                                        subjectNode.__primarylabel__ = "ServiceAccount"
                                        subjectNode.__primarykey__ = "uid"
                                    else:
                                        subjectNode = Node("AbsentServiceAccount", name=subjectName, namespace=subjectNamespace, uid=subjectName+"_"+subjectNamespace)
                                        subjectNode.__primarylabel__ = "AbsentServiceAccount"
                                        subjectNode.__primarykey__ = "uid"
                                        # print("!!!! serviceAccount related to Role: ", roleName ,", don't exist: ", subjectNamespace, ":", subjectName, sep='')

                                    try:
                                        tx = graph.begin()
                                        r1 = Relationship(projectNode, "CONTAIN SA", subjectNode)
                                        r2 = Relationship(subjectNode, "HAS ROLEBINDING", rolebindingNode)
                                        if roleKind == "ClusterRole":
                                            r3 = Relationship(rolebindingNode, "HAS CLUSTERROLE", roleNode)
                                        elif roleKind == "Role":
                                            r3 = Relationship(rolebindingNode, "HAS ROLE", roleNode)
                                        node = tx.merge(projectNode) 
                                        node = tx.merge(subjectNode) 
                                        node = tx.merge(rolebindingNode) 
                                        node = tx.merge(roleNode) 
                                        node = tx.merge(r1) 
                                        node = tx.merge(r2) 
                                        node = tx.merge(r3) 
                                        graph.commit(tx)

                                    except Exception as e: 
                                        if release:
                                            print(e)
                                            pass
                                        else:
                                            exc_type, exc_obj, exc_tb = sys.exc_info()
                                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                                            print(exc_type, fname, exc_tb.tb_lineno)
                                            print("Error:", e)
                                            sys.exit(1)

                            elif subjectKind == "Group": 
                                if "system:serviceaccount:" in subjectName:
                                    namespace = subjectName.split(":")
                                    groupNamespace = namespace[2]

                                    target_project = project_by_name.get(groupNamespace)
                                    if target_project:
                                        groupNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                                        groupNode.__primarylabel__ = "Project"
                                        groupNode.__primarykey__ = "uid"

                                    else:
                                        groupNode = Node("AbsentProject", name=groupNamespace, uid=groupNamespace)
                                        groupNode.__primarylabel__ = "AbsentProject"
                                        groupNode.__primarykey__ = "uid"

                                elif "system:" in subjectName:
                                    groupNode = Node("SystemGroup", name=subjectName, uid=subjectName)
                                    groupNode.__primarylabel__ = "SystemGroup"
                                    groupNode.__primarykey__ = "uid"

                                else:
                                    target_group = group_by_name.get(subjectName)
                                    if target_group:
                                        groupNode = Node("Group", name=target_group.metadata.name, uid=target_group.metadata.uid)
                                        groupNode.__primarylabel__ = "Group"
                                        groupNode.__primarykey__ = "uid"

                                    else:
                                        groupNode = Node("AbsentGroup", name=subjectName, uid=subjectName)
                                        groupNode.__primarylabel__ = "AbsentGroup"
                                        groupNode.__primarykey__ = "uid"

                                try:
                                    tx = graph.begin()
                                    r2 = Relationship(groupNode, "HAS ROLEBINDING", rolebindingNode)
                                    if roleKind == "ClusterRole":
                                        r3 = Relationship(rolebindingNode, "HAS CLUSTERROLE", roleNode)
                                    elif roleKind == "Role":
                                        r3 = Relationship(rolebindingNode, "HAS ROLE", roleNode)
                                    node = tx.merge(groupNode) 
                                    node = tx.merge(rolebindingNode) 
                                    node = tx.merge(roleNode) 
                                    node = tx.merge(r2) 
                                    node = tx.merge(r3) 
                                    graph.commit(tx)

                                except Exception as e: 
                                    if release:
                                        print(e)
                                        pass
                                    else:
                                        exc_type, exc_obj, exc_tb = sys.exc_info()
                                        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                                        print(exc_type, fname, exc_tb.tb_lineno)
                                        print("Error:", e)
                                        sys.exit(1)

                            elif subjectKind == "User":

                                target_user = user_by_name.get(subjectName)
                                if target_user:
                                    userNode = Node("User", name=target_user.metadata.name, uid=target_user.metadata.uid)
                                    userNode.__primarylabel__ = "User"
                                    userNode.__primarykey__ = "uid"

                                else:
                                    userNode = Node("AbsentUser", name=subjectName, uid=subjectName)
                                    userNode.__primarylabel__ = "AbsentUser"
                                    userNode.__primarykey__ = "uid"

                                try:
                                    tx = graph.begin()
                                    r2 = Relationship(userNode, "HAS ROLEBINDING", rolebindingNode)
                                    if roleKind == "ClusterRole":
                                        r3 = Relationship(rolebindingNode, "HAS CLUSTERROLE", roleNode)
                                    elif roleKind == "Role":
                                        r3 = Relationship(rolebindingNode, "HAS ROLE", roleNode)
                                    node = tx.merge(userNode) 
                                    node = tx.merge(rolebindingNode) 
                                    node = tx.merge(roleNode) 
                                    node = tx.merge(r2) 
                                    node = tx.merge(r3) 
                                    graph.commit(tx)

                                except Exception as e: 
                                    if release:
                                        print(e)
                                        pass
                                    else:
                                        exc_type, exc_obj, exc_tb = sys.exc_info()
                                        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                                        print(exc_type, fname, exc_tb.tb_lineno)
                                        print("Error:", e)
                                        sys.exit(1)

                            else:
                                print("[-] RoleBinding subjectKind not handled", subjectKind)


def _collect_clusterrolebinding(ctx):
    """Collect ClusterRoleBinding resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## ClusterRoleBinding
    ## 
    print(SECTION_HEADERS["cluster_role_binding"])

    if _should_collect(collector, "clusterrolebinding"):
        existing_count = graph.nodes.match("ClusterRoleBinding").count()
        if existing_count >= len(clusterRoleBinding_list.items):
            print(f"⚠️ Database already has {existing_count} ClusterRoleBinding nodes, skipping import.")
        else:
            with Bar('ClusterRoleBinding',max = len(clusterRoleBinding_list.items)) as bar:
                for enum in clusterRoleBinding_list.items:
                    bar.next()

                    # print(enum)
                    name = enum.metadata.name
                    uid = enum.metadata.uid
                    namespace = enum.metadata.namespace

                    roleKind = enum.roleRef.kind
                    roleName = enum.roleRef.name
                    subjects = list(enum.subjects or [])

                    risk_tags = []
                    high_priv_roles = {"cluster-admin", "system:masters", "system:admin"}
                    if roleKind == "ClusterRole" and roleName in high_priv_roles:
                        risk_tags.append("⚠️ grants cluster-admin access")
                    if not subjects:
                        risk_tags.append("⚠️ no subjects bound")

                    for subject in subjects:
                        subjectKind = getattr(subject, "kind", "")
                        subjectName = getattr(subject, "name", "")
                        if subjectKind == "Group" and subjectName in {"system:authenticated", "system:unauthenticated"}:
                            risk_tags.append(f"⚠️ binds {subjectName}")
                        if subjectKind == "User" and subjectName in {"kube:admin", "system:admin"}:
                            risk_tags.append("⚠️ admin user bound")
                        if subjectKind == "ServiceAccount" and subjectName == "default":
                            risk_tags.append("⚠️ default service account escalation")

                    clusterRolebindingNode = Node(
                        "ClusterRoleBinding",
                        name=name,
                        namespace=namespace,
                        uid=uid,
                        risk=format_risk_tags(risk_tags, default="✅ normal")
                    )
                    clusterRolebindingNode.__primarylabel__ = "ClusterRoleBinding"
                    clusterRolebindingNode.__primarykey__ = "uid"

                    if roleKind == "ClusterRole":
                        target_clusterroles = clusterrole_by_name.get(roleName)
                        if target_clusterroles:
                            roleNode = Node("ClusterRole",name=target_clusterroles.metadata.name, uid=target_clusterroles.metadata.uid)
                            roleNode.__primarylabel__ = "ClusterRole"
                            roleNode.__primarykey__ = "uid"

                        else:
                            roleNode = Node("AbsentClusterRole",name=roleName, uid=roleName)
                            roleNode.__primarylabel__ = "AbsentClusterRole"
                            roleNode.__primarykey__ = "uid"

                    elif roleKind == "Role":
                        target_role = role_by_ns_name.get((enum.metadata.namespace, roleName))
                        if target_role:
                            roleNode = Node("Role",name=target_role.metadata.name, namespace=target_role.metadata.namespace, uid=target_role.metadata.uid)
                            roleNode.__primarylabel__ = "Role"
                            roleNode.__primarykey__ = "uid"

                        else:
                            roleNode = Node("AbsentRole",name=roleName, namespace=namespace, uid=roleName+"_"+namespace)
                            roleNode.__primarylabel__ = "AbsentRole"
                            roleNode.__primarykey__ = "uid"

                    if subjects:
                        for subject in subjects:
                            subjectKind = subject.kind
                            subjectName = subject.name
                            subjectNamespace = subject.namespace

                            if subjectKind == "ServiceAccount":
                                if subjectNamespace:
                                    target_project = project_by_name.get(subjectNamespace)
                                    if target_project:
                                        projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                                        projectNode.__primarylabel__ = "Project"
                                        projectNode.__primarykey__ = "uid"

                                    else:
                                        projectNode = Node("AbsentProject", name=subjectNamespace, uid=subjectNamespace)
                                        projectNode.__primarylabel__ = "AbsentProject"
                                        projectNode.__primarykey__ = "uid"

                                    target_sa = serviceaccount_by_ns_name.get((subjectNamespace, subjectName))
                                    if target_sa:
                                        subjectNode = Node("ServiceAccount",name=target_sa.metadata.name, namespace=target_sa.metadata.namespace, uid=target_sa.metadata.uid)
                                        subjectNode.__primarylabel__ = "ServiceAccount"
                                        subjectNode.__primarykey__ = "uid"

                                    else:
                                        subjectNode = Node("AbsentServiceAccount", name=subjectName, namespace=subjectNamespace, uid=subjectName+"_"+subjectNamespace)
                                        subjectNode.__primarylabel__ = "AbsentServiceAccount"
                                        subjectNode.__primarykey__ = "uid"
                                        # print("!!!! serviceAccount related to Role: ", roleName ,", don't exist: ", subjectNamespace, ":", subjectName, sep='')

                                    try: 
                                        tx = graph.begin()
                                        r1 = Relationship(projectNode, "CONTAIN SA", subjectNode)
                                        r2 = Relationship(subjectNode, "HAS CLUSTERROLEBINDING", clusterRolebindingNode)
                                        if roleKind == "ClusterRole":
                                            r3 = Relationship(clusterRolebindingNode, "HAS CLUSTERROLE", roleNode)
                                        elif roleKind == "Role":
                                            r3 = Relationship(clusterRolebindingNode, "HAS ROLE", roleNode)
                                        node = tx.merge(projectNode) 
                                        node = tx.merge(subjectNode) 
                                        node = tx.merge(clusterRolebindingNode) 
                                        node = tx.merge(roleNode) 
                                        node = tx.merge(r1) 
                                        node = tx.merge(r2) 
                                        node = tx.merge(r3) 
                                        graph.commit(tx)

                                    except Exception as e: 
                                        if release:
                                            print(e)
                                            pass
                                        else:
                                            exc_type, exc_obj, exc_tb = sys.exc_info()
                                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                                            print(exc_type, fname, exc_tb.tb_lineno)
                                            print("Error:", e)
                                            sys.exit(1)

                            elif subjectKind == "Group": 
                                if "system:serviceaccount:" in subjectName:
                                    namespace = subjectName.split(":")
                                    groupNamespace = namespace[2]

                                    target_project = project_by_name.get(groupNamespace)
                                    if target_project:
                                        groupNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                                        groupNode.__primarylabel__ = "Project"
                                        groupNode.__primarykey__ = "uid"

                                    else:
                                        groupNode = Node("AbsentProject", name=groupNamespace, uid=groupNamespace)
                                        groupNode.__primarylabel__ = "AbsentProject"
                                        groupNode.__primarykey__ = "uid"

                                elif "system:" in subjectName:
                                    groupNode = Node("SystemGroup", name=subjectName, uid=subjectName)
                                    groupNode.__primarylabel__ = "SystemGroup"
                                    groupNode.__primarykey__ = "uid"

                                else:
                                    target_group = group_by_name.get(subjectName)
                                    if target_group:
                                        groupNode = Node("Group", name=target_group.metadata.name, uid=target_group.metadata.uid)
                                        groupNode.__primarylabel__ = "Group"
                                        groupNode.__primarykey__ = "uid"

                                    else:
                                        groupNode = Node("AbsentGroup", name=subjectName, uid=subjectName)
                                        groupNode.__primarylabel__ = "AbsentGroup"
                                        groupNode.__primarykey__ = "uid"

                                try:
                                    tx = graph.begin()
                                    r2 = Relationship(groupNode, "HAS CLUSTERROLEBINDING", clusterRolebindingNode)
                                    if roleKind == "ClusterRole":
                                        r3 = Relationship(clusterRolebindingNode, "HAS CLUSTERROLE", roleNode)
                                    elif roleKind == "Role":
                                        r3 = Relationship(clusterRolebindingNode, "HAS ROLE", roleNode)
                                    node = tx.merge(groupNode) 
                                    node = tx.merge(clusterRolebindingNode) 
                                    node = tx.merge(roleNode) 
                                    node = tx.merge(r2) 
                                    node = tx.merge(r3) 
                                    graph.commit(tx)

                                except Exception as e: 
                                    if release:
                                        print(e)
                                        pass
                                    else:
                                        exc_type, exc_obj, exc_tb = sys.exc_info()
                                        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                                        print(exc_type, fname, exc_tb.tb_lineno)
                                        print("Error:", e)
                                        sys.exit(1)

                            elif subjectKind == "User": 

                                target_user = user_by_name.get(subjectName)
                                if target_user:
                                    userNode = Node("User", name=target_user.metadata.name, uid=target_user.metadata.uid)
                                    userNode.__primarylabel__ = "User"
                                    userNode.__primarykey__ = "uid"

                                else:
                                    userNode = Node("AbsentUser", name=subjectName, uid=subjectName)
                                    userNode.__primarylabel__ = "AbsentUser"
                                    userNode.__primarykey__ = "uid"

                                try:
                                    tx = graph.begin()
                                    r2 = Relationship(userNode, "HAS CLUSTERROLEBINDING", clusterRolebindingNode)
                                    if roleKind == "ClusterRole":
                                        r3 = Relationship(clusterRolebindingNode, "HAS CLUSTERROLE", roleNode)
                                    elif roleKind == "Role":
                                        r3 = Relationship(clusterRolebindingNode, "HAS ROLE", roleNode)
                                    node = tx.merge(userNode) 
                                    node = tx.merge(clusterRolebindingNode) 
                                    node = tx.merge(roleNode) 
                                    node = tx.merge(r2) 
                                    node = tx.merge(r3) 
                                    graph.commit(tx)

                                except Exception as e: 
                                    if release:
                                        print(e)
                                        pass
                                    else:
                                        exc_type, exc_obj, exc_tb = sys.exc_info()
                                        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                                        print(exc_type, fname, exc_tb.tb_lineno)
                                        print("Error:", e)
                                        sys.exit(1)

                            else:
                                print("[-] RoleBinding subjectKind not handled", subjectKind)


def _collect_route(ctx):
    """Collect Route resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## Route
    ## 
    print(SECTION_HEADERS["route"])

    if _should_collect(collector, "route"):
        existing_count = graph.nodes.match("Route").count()
        if existing_count >= len(route_list.items):
            print(f"⚠️ Database already has {existing_count} Route nodes, skipping import.")
        else:
            with Bar('Route', max=len(route_list.items)) as bar:
                for enum in route_list.items:
                    bar.next()

                    # ───────────────────────────────
                    # Metadata and basic fields
                    # ───────────────────────────────
                    name = getattr(enum.metadata, "name", "unknown-route")
                    namespace = getattr(enum.metadata, "namespace", "unknown-namespace")
                    uid = getattr(enum.metadata, "uid", f"{namespace}:{name}")

                    spec = getattr(enum, "spec", None)
                    host = getattr(spec, "host", None)
                    path = getattr(spec, "path", None)

                    # Extract target port and service
                    port = "any"
                    service_name = None
                    if spec and hasattr(spec, "port") and getattr(spec, "port", None):
                        port = getattr(spec.port, "targetPort", "any")
                    if spec and hasattr(spec, "to") and getattr(spec, "to", None):
                        service_name = getattr(spec.to, "name", None)

                    # Extract TLS details if present
                    tls = getattr(spec, "tls", None)
                    tls_termination = getattr(tls, "termination", None) if tls else None
                    insecure_policy = getattr(tls, "insecureEdgeTerminationPolicy", None) if tls else None

                    # ───────────────────────────────
                    # Determine security/risk level
                    # ───────────────────────────────
                    risk_tags = []
                    if not tls:
                        risk_tags.append("⚠️ no TLS")
                    elif insecure_policy and insecure_policy.lower() == "allow":
                        risk_tags.append("⚠️ allows insecure (HTTP)")
                    elif tls_termination and tls_termination.lower() in ["edge", "passthrough"]:
                        # Edge termination can be OK, but note if HTTP allowed
                        if insecure_policy and insecure_policy.lower() != "none":
                            risk_tags.append("⚠️ partially insecure (edge HTTP fallback)")

                    if host and ("*" in host or host.startswith("0.0.0.0")):
                        risk_tags.append("⚠️ wildcard host")

                    # Routes pointing to internal or system namespaces
                    if namespace.startswith("openshift") or namespace.startswith("kube-"):
                        risk_tags.append("⚠️ system namespace exposure")

                    risk_str = ", ".join(risk_tags) if risk_tags else "✅ secure"

                    # ───────────────────────────────
                    # Project relationship
                    # ───────────────────────────────
                    target_project = project_by_name.get(namespace)
                    if target_project:
                        projectNode = Node(
                            "Project",
                            name=target_project.metadata.name,
                            uid=target_project.metadata.uid
                        )
                        projectNode.__primarylabel__ = "Project"
                        projectNode.__primarykey__ = "uid"
                    else:
                        projectNode = Node("AbsentProject", name=namespace, uid=namespace)
                        projectNode.__primarylabel__ = "AbsentProject"
                        projectNode.__primarykey__ = "uid"

                    # ───────────────────────────────
                    # Create Route node
                    # ───────────────────────────────
                    routeNode = Node(
                        "Route",
                        name=name,
                        namespace=namespace,
                        uid=uid,
                        host=host,
                        port=str(port),
                        path=path,
                        service=service_name,
                        tlsTermination=tls_termination,
                        insecurePolicy=insecure_policy,
                        risk=risk_str
                    )
                    routeNode.__primarylabel__ = "Route"
                    routeNode.__primarykey__ = "uid"

                    # ───────────────────────────────
                    # Commit to Neo4j
                    # ───────────────────────────────
                    try:
                        tx = graph.begin()
                        rel = Relationship(projectNode, "CONTAINS_ROUTE", routeNode)
                        tx.merge(projectNode)
                        tx.merge(routeNode)
                        tx.merge(rel)
                        graph.commit(tx)

                    except Exception as e:
                        if release:
                            print(e)
                            pass
                        else:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            print(exc_type, fname, exc_tb.tb_lineno)
                            print("Error:", e)
                            sys.exit(1)


def _collect_pod(ctx):
    """Collect Pod resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## Pod
    ## 
    print(SECTION_HEADERS["pod"])

    if _should_collect(collector, "pod"):
        existing_count = graph.nodes.match("Pod").count()
        if existing_count >= len(pod_list.items):
            print(f"⚠️ Database already has {existing_count} Pod nodes, skipping import.")
        else:
            with Bar('Pod',max = len(pod_list.items)) as bar:
                for enum in pod_list.items:
                    bar.next()
                    # print(enum.metadata)

                    name = enum.metadata.name
                    namespace = enum.metadata.namespace
                    uid = enum.metadata.uid

                    target_project = project_by_name.get(namespace)
                    if target_project:
                        projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                        projectNode.__primarylabel__ = "Project"
                        projectNode.__primarykey__ = "uid"

                    else:
                        projectNode = Node("AbsentProject",name=namespace)
                        projectNode.__primarylabel__ = "AbsentProject"
                        projectNode.__primarykey__ = "name"

                    pod_spec = getattr(enum, "spec", None)
                    pod_status = getattr(enum, "status", None)
                    service_account = getattr(pod_spec, "serviceAccountName", None) if pod_spec else None
                    host_network = getattr(pod_spec, "hostNetwork", False) if pod_spec else False
                    host_pid = getattr(pod_spec, "hostPID", False) if pod_spec else False
                    host_ipc = getattr(pod_spec, "hostIPC", False) if pod_spec else False

                    risk_tags = []
                    if host_network:
                        risk_tags.append("⚠️ hostNetwork enabled")
                    if host_pid:
                        risk_tags.append("⚠️ hostPID enabled")
                    if host_ipc:
                        risk_tags.append("⚠️ hostIPC enabled")

                    containers = list(getattr(pod_spec, "containers", []) or []) if pod_spec else []
                    images = []
                    for container in containers:
                        image = getattr(container, "image", None)
                        if image:
                            images.append(image)
                            if ":" not in image or image.endswith(":latest"):
                                risk_tags.append(f"⚠️ floating image tag ({image})")

                        security_context = getattr(container, "security_context", None)
                        if not security_context:
                            security_context = getattr(container, "securityContext", None)
                        if security_context:
                            if getattr(security_context, "privileged", False):
                                risk_tags.append("⚠️ privileged container")
                            if getattr(security_context, "allow_privilege_escalation", False):
                                risk_tags.append("⚠️ allows privilege escalation")
                            run_as_user = getattr(security_context, "run_as_user", None)
                            if run_as_user in (0, "0"):
                                risk_tags.append("⚠️ runs as root")

                    volumes = list(getattr(pod_spec, "volumes", []) or []) if pod_spec else []
                    for volume in volumes:
                        host_path = getattr(volume, "host_path", None)
                        if not host_path:
                            host_path = getattr(volume, "hostPath", None)
                        if host_path:
                            risk_tags.append("⚠️ hostPath volume")

                    phase = getattr(pod_status, "phase", None)
                    if phase and phase.lower() not in {"running", "succeeded"}:
                        risk_tags.append(f"⚠️ phase={phase}")

                    podNode = Node(
                        "Pod",
                        name=name,
                        namespace=namespace,
                        uid=uid,
                        serviceAccount=service_account,
                        hostNetwork=host_network,
                        hostPID=host_pid,
                        hostIPC=host_ipc,
                        images=",".join(images),
                        phase=phase,
                        risk=format_risk_tags(risk_tags)
                    )
                    podNode.__primarylabel__ = "Pod"
                    podNode.__primarykey__ = "uid"

                    try:
                        tx = graph.begin()
                        relationShip = Relationship(projectNode, "CONTAIN POD", podNode)
                        node = tx.merge(projectNode) 
                        node = tx.merge(podNode) 
                        node = tx.merge(relationShip) 
                        graph.commit(tx)

                    except Exception as e: 
                        if release:
                            print(e)
                            pass
                        else:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            print(exc_type, fname, exc_tb.tb_lineno)
                            print("Error:", e)
                            sys.exit(1)


def _collect_configmap(ctx):
    """Collect ConfigMap resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## ConfigMap
    ## 
    print(SECTION_HEADERS["configmap"])

    if _should_collect(collector, "configmap"):
        existing_count = graph.nodes.match("ConfigMap").count()
        if existing_count >= len(configmap_list.items):
            print(f"⚠️ Database already has {existing_count} ConfigMap nodes, skipping import.")
        else:
            with Bar('ConfigMap',max = len(configmap_list.items)) as bar:
                for enum in configmap_list.items:
                    bar.next()
                    # print(enum.metadata)

                    name = enum.metadata.name
                    namespace = enum.metadata.namespace
                    uid = enum.metadata.uid

                    target_project = project_by_name.get(namespace)
                    if target_project:
                        projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                        projectNode.__primarylabel__ = "Project"
                        projectNode.__primarykey__ = "uid"

                    else:
                        projectNode = Node("AbsentProject",name=namespace)
                        projectNode.__primarylabel__ = "AbsentProject"
                        projectNode.__primarykey__ = "name"

                    data = getattr(enum, "data", {}) or {}
                    binary_data = getattr(enum, "binaryData", {}) or {}
                    immutable = getattr(enum, "immutable", False)

                    risk_tags = []
                    sensitive_markers = {"password", "token", "secret", "key", "cert"}
                    for key in list(data.keys()) + list(binary_data.keys()):
                        if any(marker in key.lower() for marker in sensitive_markers):
                            risk_tags.append(f"⚠️ sensitive key '{key}'")
                    if not immutable and risk_tags:
                        risk_tags.append("⚠️ mutable sensitive data")

                    configmapNode = Node(
                        "ConfigMap",
                        name=name,
                        namespace=namespace,
                        uid=uid,
                        immutable=immutable,
                        risk=format_risk_tags(risk_tags)
                    )
                    configmapNode.__primarylabel__ = "ConfigMap"
                    configmapNode.__primarykey__ = "uid"

                    try:
                        tx = graph.begin()
                        relationShip = Relationship(projectNode, "CONTAIN CONFIGMAP", configmapNode)
                        node = tx.merge(projectNode) 
                        node = tx.merge(configmapNode) 
                        node = tx.merge(relationShip) 
                        graph.commit(tx)

                    except Exception as e: 
                        if release:
                            print(e)
                            pass
                        else:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            print(exc_type, fname, exc_tb.tb_lineno)
                            print("Error:", e)
                            sys.exit(1)


def _collect_kyverno(ctx):
    """Collect Kyverno resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## Kyverno 
    ## 
    print(SECTION_HEADERS["kyverno"])

    if _should_collect(collector, "kyverno"):
        existing_count = graph.nodes.match("KyvernoWhitelist").count()
        if existing_count >= len(kyverno_logs):
            print(f"⚠️ Database already has {existing_count} KyvernoWhitelist nodes, skipping import.")
        else:
            with Bar('Kyverno',max = len(kyverno_logs)) as bar:
                for logs in kyverno_logs.values():
                    bar.next()

                    # TODO do the same with excludeGroups, excludeRoles, excludedClusterRoles
                    try:
                        excludedUsernameList = re.search(r'excludeUsernames=\[(.+?)\]', str(logs), re.IGNORECASE).group(1)
                        excludedUsernameList = excludedUsernameList.split(",")
                    except Exception as t:
                        print("\n[-] error excludeUsernames: "+ str(t))  
                        continue

                    for subject in excludedUsernameList:
                        subject=subject.replace('"', '')
                        split = subject.split(":")

                        if len(split)==4:
                            if "serviceaccount" ==  split[1]:

                                subjectNamespace = split[2]
                                subjectName = split[3]

                                if subjectNamespace:
                                    target_project = project_by_name.get(subjectNamespace)
                                    if target_project:
                                        projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                                        projectNode.__primarylabel__ = "Project"
                                        projectNode.__primarykey__ = "uid"

                                    else:
                                        projectNode = Node("AbsentProject", name=subjectNamespace, uid=subjectNamespace)
                                        projectNode.__primarylabel__ = "AbsentProject"
                                        projectNode.__primarykey__ = "uid"

                                    target_sa = serviceaccount_by_ns_name.get((subjectNamespace, subjectName))
                                    if target_sa:
                                        subjectNode = Node("ServiceAccount",name=target_sa.metadata.name, namespace=target_sa.metadata.namespace, uid=target_sa.metadata.uid)
                                        subjectNode.__primarylabel__ = "ServiceAccount"
                                        subjectNode.__primarykey__ = "uid"

                                    else:
                                        subjectNode = Node("AbsentServiceAccount", name=subjectName, namespace=subjectNamespace, uid=subjectName+"_"+subjectNamespace)
                                        subjectNode.__primarylabel__ = "AbsentServiceAccount"
                                        subjectNode.__primarykey__ = "uid"

                                    try:
                                        kyvernoWhitelistNode = Node(
                                            "KyvernoWhitelist",
                                            name="KyvernoWhitelist",
                                            uid="KyvernoWhitelist",
                                            risk=format_risk_tags(["⚠️ bypasses Kyverno policies"])
                                        )
                                        kyvernoWhitelistNode.__primarylabel__ = "KyvernoWhitelist"
                                        kyvernoWhitelistNode.__primarykey__ = "uid"


                                        tx = graph.begin()
                                        r1 = Relationship(projectNode, "CONTAIN SA", subjectNode)
                                        r2 = Relationship(subjectNode, "CAN BYPASS KYVERNO", kyvernoWhitelistNode)

                                        node = tx.merge(projectNode) 
                                        node = tx.merge(subjectNode) 
                                        node = tx.merge(kyvernoWhitelistNode) 
                                        node = tx.merge(r1) 
                                        node = tx.merge(r2) 
                                        graph.commit(tx)

                                    except Exception as e: 
                                        if release:
                                            print(e)
                                            pass
                                        else:
                                            exc_type, exc_obj, exc_tb = sys.exc_info()
                                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                                            print(exc_type, fname, exc_tb.tb_lineno)
                                            print("Error:", e)
                                            sys.exit(1)


def _collect_validatingwebhookconfiguration(ctx):
    """Collect ValidatingWebhookConfiguration resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## ValidatingWebhookConfiguration 
    ## 
    print(SECTION_HEADERS["validating_webhook_configuration"])

    if _should_collect(collector, "validatingwebhookconfiguration"):
        existing_count = graph.nodes.match("ValidatingWebhookConfiguration").count()
        if existing_count >= len(validatingWebhookConfiguration_list.items):
            print(f"⚠️ Database already has {existing_count} ValidatingWebhookConfiguration nodes, skipping import.")
        else:
            with Bar('ValidatingWebhookConfiguration', max=len(validatingWebhookConfiguration_list.items)) as bar:
                for enum in validatingWebhookConfiguration_list.items:
                    bar.next()
                    config_name = getattr(enum.metadata, "name", None)
                    if not config_name:
                        continue

                    # ───────────────────────────────
                    # Create the parent Configuration node
                    # ───────────────────────────────
                    webhooks = list(getattr(enum, "webhooks", []) or [])
                    cfg_risk_tags = []
                    if not webhooks:
                        cfg_risk_tags.append("⚠️ no webhooks configured")

                    cfgNode = Node(
                        "ValidatingWebhookConfiguration",
                        name=config_name,
                        uid=getattr(enum.metadata, "uid", config_name),
                        risk=format_risk_tags(cfg_risk_tags)
                    )
                    cfgNode.__primarylabel__ = "ValidatingWebhookConfiguration"
                    cfgNode.__primarykey__ = "uid"

                    tx = graph.begin()
                    tx.merge(cfgNode)
                    graph.commit(tx)

                    # ───────────────────────────────
                    # Handle each webhook under it
                    # ───────────────────────────────
                    for webhook in webhooks:
                        webhook_name = getattr(webhook, "name", "unknown-webhook")

                        # Core webhook properties
                        failure_policy = getattr(webhook, "failurePolicy", None)
                        side_effects = getattr(webhook, "sideEffects", None)
                        timeout = getattr(webhook, "timeoutSeconds", None)
                        admission_review_versions = getattr(webhook, "admissionReviewVersions", None)
                        rules = getattr(webhook, "rules", [])
                        client_config = getattr(webhook, "clientConfig", None)

                        webhook_risk_tags = []
                        if failure_policy and failure_policy.lower() == "ignore":
                            webhook_risk_tags.append("⚠️ failurePolicy=Ignore")
                        if not getattr(webhook, "namespaceSelector", None):
                            webhook_risk_tags.append("⚠️ cluster-wide scope")
                        if side_effects and side_effects.lower() in {"some", "unknown"}:
                            webhook_risk_tags.append(f"⚠️ sideEffects={side_effects}")
                        if timeout and timeout > 10:
                            webhook_risk_tags.append(f"⚠️ long timeout ({timeout}s)")

                        # Extract namespace selector (if any)
                        ns_selector = getattr(webhook, "namespaceSelector", None)
                        ns_expressions = []
                        if ns_selector and hasattr(ns_selector, "matchExpressions"):
                            for expr in ns_selector.matchExpressions or []:
                                key = getattr(expr, "key", "")
                                op = getattr(expr, "operator", "")
                                vals = getattr(expr, "values", [])
                                ns_expressions.append(f"{key} {op} {vals}")
                        ns_str = ", ".join(ns_expressions) if ns_expressions else "None"

                        # Extract object selector (if any)
                        obj_selector = getattr(webhook, "objectSelector", None)
                        obj_expressions = []
                        if obj_selector and hasattr(obj_selector, "matchExpressions"):
                            for expr in obj_selector.matchExpressions or []:
                                key = getattr(expr, "key", "")
                                op = getattr(expr, "operator", "")
                                vals = getattr(expr, "values", [])
                                obj_expressions.append(f"{key} {op} {vals}")
                        obj_str = ", ".join(obj_expressions) if obj_expressions else "None"

                        # Build rules summary (verbs, apiGroups, etc.)
                        rule_summaries = []
                        for rule in rules:
                            apis = getattr(rule, "apiGroups", None) or []
                            resources = getattr(rule, "resources", None) or []
                            verbs = getattr(rule, "verbs", None) or []
                            rule_summaries.append(f"APIs={apis} RES={resources} VERBS={verbs}")
                            if "*" in apis or "*" in resources or "*" in verbs:
                                webhook_risk_tags.append("⚠️ wildcard rule scope")
                        rules_str = "; ".join(rule_summaries) if rule_summaries else "None"

                        # Optional: capture client service reference
                        svc_ref = None
                        if client_config and hasattr(client_config, "service"):
                            svc = client_config.service
                            svc_ref = f"{getattr(svc, 'namespace', '')}/{getattr(svc, 'name', '')}"

                        try:
                            validatingWebhookNode = Node(
                                "ValidatingWebhook",
                                name=webhook_name,
                                parentConfig=config_name,
                                uid=f"{config_name}:{webhook_name}",
                                failurePolicy=failure_policy,
                                sideEffects=side_effects,
                                timeout=timeout,
                                admissionReviewVersions=str(admission_review_versions),
                                namespaceSelector=ns_str,
                                objectSelector=obj_str,
                                rules=rules_str,
                                serviceRef=svc_ref,
                                risk=format_risk_tags(webhook_risk_tags)
                            )
                            validatingWebhookNode.__primarylabel__ = "ValidatingWebhook"
                            validatingWebhookNode.__primarykey__ = "uid"

                            tx = graph.begin()
                            tx.merge(validatingWebhookNode)

                            # Create relationship to parent
                            rel = Relationship(cfgNode, "CONTAINS_WEBHOOK", validatingWebhookNode)
                            tx.merge(rel)
                            graph.commit(tx)

                        except Exception as e:
                            if release:
                                print(e)
                                pass
                            else:
                                exc_type, exc_obj, exc_tb = sys.exc_info()
                                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                                print(exc_type, fname, exc_tb.tb_lineno)
                                print("Error:", e)
                                sys.exit(1)


def _collect_mutatingwebhookconfiguration(ctx):
    """Collect MutatingWebhookConfiguration resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## MutatingWebhookConfiguration 
    ## 
    print(SECTION_HEADERS["mutating_webhook_configuration"])

    if _should_collect(collector, "mutatingwebhookconfiguration"):
        existing_count = graph.nodes.match("MutatingWebhookConfiguration").count()
        if existing_count >= len(mutatingWebhookConfiguration_list.items):
            print(f"⚠️ Database already has {existing_count} MutatingWebhookConfiguration nodes, skipping import.")
        else:
            with Bar('MutatingWebhookConfiguration', max=len(mutatingWebhookConfiguration_list.items)) as bar:
                for enum in mutatingWebhookConfiguration_list.items:
                    bar.next()
                    config_name = getattr(enum.metadata, "name", None)
                    if not config_name:
                        continue

                    # ───────────────────────────────
                    # Create parent configuration node
                    # ───────────────────────────────
                    webhooks = list(getattr(enum, "webhooks", []) or [])
                    cfg_risk_tags = []
                    if not webhooks:
                        cfg_risk_tags.append("⚠️ no webhooks configured")

                    cfgNode = Node(
                        "MutatingWebhookConfiguration",
                        name=config_name,
                        uid=getattr(enum.metadata, "uid", config_name),
                        risk=format_risk_tags(cfg_risk_tags)
                    )
                    cfgNode.__primarylabel__ = "MutatingWebhookConfiguration"
                    cfgNode.__primarykey__ = "uid"

                    tx = graph.begin()
                    tx.merge(cfgNode)
                    graph.commit(tx)

                    # ───────────────────────────────
                    # Iterate through webhooks
                    # ───────────────────────────────
                    for webhook in webhooks:
                        webhook_name = getattr(webhook, "name", "unknown-webhook")
                        failure_policy = getattr(webhook, "failurePolicy", None)
                        side_effects = getattr(webhook, "sideEffects", None)
                        timeout = getattr(webhook, "timeoutSeconds", None)
                        admission_review_versions = getattr(webhook, "admissionReviewVersions", None)
                        reinvocation_policy = getattr(webhook, "reinvocationPolicy", None)
                        match_policy = getattr(webhook, "matchPolicy", None)

                        webhook_risk_tags = []
                        if failure_policy and failure_policy.lower() == "ignore":
                            webhook_risk_tags.append("⚠️ failurePolicy=Ignore")
                        if side_effects and side_effects.lower() in {"some", "unknown"}:
                            webhook_risk_tags.append(f"⚠️ sideEffects={side_effects}")
                        if timeout and timeout > 10:
                            webhook_risk_tags.append(f"⚠️ long timeout ({timeout}s)")
                        if match_policy and match_policy.lower() == "exact":
                            webhook_risk_tags.append("⚠️ matchPolicy=Exact (may miss objects)")

                        # Namespace selector
                        ns_selector = getattr(webhook, "namespaceSelector", None)
                        ns_expressions = []
                        if ns_selector and hasattr(ns_selector, "matchExpressions"):
                            for expr in ns_selector.matchExpressions or []:
                                key = getattr(expr, "key", "")
                                op = getattr(expr, "operator", "")
                                vals = getattr(expr, "values", [])
                                ns_expressions.append(f"{key} {op} {vals}")
                        ns_str = ", ".join(ns_expressions) if ns_expressions else "None"

                        # Object selector
                        obj_selector = getattr(webhook, "objectSelector", None)
                        obj_expressions = []
                        if obj_selector and hasattr(obj_selector, "matchExpressions"):
                            for expr in obj_selector.matchExpressions or []:
                                key = getattr(expr, "key", "")
                                op = getattr(expr, "operator", "")
                                vals = getattr(expr, "values", [])
                                obj_expressions.append(f"{key} {op} {vals}")
                        obj_str = ", ".join(obj_expressions) if obj_expressions else "None"

                        # Rules summary
                        rules = getattr(webhook, "rules", [])
                        rule_summaries = []
                        for rule in rules:
                            apis = getattr(rule, "apiGroups", [])
                            resources = getattr(rule, "resources", [])
                            verbs = getattr(rule, "verbs", [])
                            operations = getattr(rule, "operations", [])
                            rule_summaries.append(f"APIs={apis} RES={resources} OPS={operations} VERBS={verbs}")
                            if "*" in apis or "*" in resources or "*" in operations:
                                webhook_risk_tags.append("⚠️ wildcard rule scope")
                        rules_str = "; ".join(rule_summaries) if rule_summaries else "None"

                        # Service reference
                        svc_ref = None
                        client_config = getattr(webhook, "clientConfig", None)
                        if client_config and hasattr(client_config, "service"):
                            svc = client_config.service
                            svc_ref = f"{getattr(svc, 'namespace', '')}/{getattr(svc, 'name', '')}{getattr(client_config, 'path', '')}"

                        try:
                            webhookNode = Node(
                                "MutatingWebhook",
                                name=webhook_name,
                                uid=f"{config_name}:{webhook_name}",
                                failurePolicy=failure_policy,
                                sideEffects=side_effects,
                                timeout=timeout,
                                reinvocationPolicy=reinvocation_policy,
                                matchPolicy=match_policy,
                                admissionReviewVersions=str(admission_review_versions),
                                namespaceSelector=ns_str,
                                objectSelector=obj_str,
                                rules=rules_str,
                                serviceRef=svc_ref,
                                risk=format_risk_tags(webhook_risk_tags)
                            )
                            webhookNode.__primarylabel__ = "MutatingWebhook"
                            webhookNode.__primarykey__ = "uid"

                            tx = graph.begin()
                            tx.merge(webhookNode)
                            rel = Relationship(cfgNode, "CONTAINS_WEBHOOK", webhookNode)
                            tx.merge(rel)
                            graph.commit(tx)

                        except Exception as e:
                            if release:
                                print(e)
                                pass
                            else:
                                exc_type, exc_obj, exc_tb = sys.exc_info()
                                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                                print(exc_type, fname, exc_tb.tb_lineno)
                                print("Error:", e)
                                sys.exit(1)


def _collect_clusterpolicy(ctx):
    """Collect ClusterPolicy resources."""
    collector = ctx.collector
    graph = ctx.graph
    release = ctx.release
    oauth_list = ctx.oauth_list
    identity_list = ctx.identity_list
    project_list = ctx.project_list
    serviceAccount_list = ctx.serviceAccount_list
    security_context_constraints_list = ctx.security_context_constraints_list
    role_list = ctx.role_list
    clusterrole_list = ctx.clusterrole_list
    user_list = ctx.user_list
    group_list = ctx.group_list
    roleBinding_list = ctx.roleBinding_list
    clusterRoleBinding_list = ctx.clusterRoleBinding_list
    route_list = ctx.route_list
    pod_list = ctx.pod_list
    kyverno_logs = ctx.kyverno_logs
    configmap_list = ctx.configmap_list
    validatingWebhookConfiguration_list = ctx.validatingWebhookConfiguration_list
    mutatingWebhookConfiguration_list = ctx.mutatingWebhookConfiguration_list
    clusterPolicy_list = ctx.clusterPolicy_list
    project_by_name = ctx.project_by_name
    serviceaccount_by_ns_name = ctx.serviceaccount_by_ns_name
    security_context_constraints_by_name = ctx.security_context_constraints_by_name
    role_by_ns_name = ctx.role_by_ns_name
    clusterrole_by_name = ctx.clusterrole_by_name
    user_by_name = ctx.user_by_name
    group_by_name = ctx.group_by_name
    ##
    ## ClusterPolicy 
    ## 
    print(SECTION_HEADERS["cluster_policy"])

    if _should_collect(collector, "clusterpolicies"):
        existing_count = graph.nodes.match("ClusterPolicy").count()
        if existing_count >= len(clusterPolicy_list.items):
            print(f"⚠️ Database already has {existing_count} ClusterPolicy nodes, skipping import.")
        else:
            with Bar('ClusterPolicies', max=len(clusterPolicy_list.items)) as bar:
                for enum in clusterPolicy_list.items:
                    bar.next()
                    name = getattr(enum.metadata, "name", None)
                    if not name:
                        continue

                    spec = getattr(enum, "spec", None)
                    enforcement = getattr(spec, "validationFailureAction", "Audit")
                    background = getattr(spec, "background", None)
                    validationFailureActionOverrides = getattr(spec, "validationFailureActionOverrides", None)

                    policy_risk_tags = []
                    if enforcement and str(enforcement).lower() != "enforce":
                        policy_risk_tags.append(f"⚠️ enforcement={enforcement}")
                    if background is False:
                        policy_risk_tags.append("⚠️ background scanning disabled")
                    if validationFailureActionOverrides:
                        policy_risk_tags.append("⚠️ overrides weaken enforcement")

                    try:
                        # Create ClusterPolicy node
                        cpNode = Node(
                            "ClusterPolicy",
                            name=name,
                            uid=getattr(enum.metadata, "uid", name),
                            enforcement=enforcement,
                            background=background,
                            overrides=str(validationFailureActionOverrides),
                            risk=format_risk_tags(policy_risk_tags)
                        )
                        cpNode.__primarylabel__ = "ClusterPolicy"
                        cpNode.__primarykey__ = "uid"

                        tx = graph.begin()
                        tx.merge(cpNode)
                        graph.commit(tx)

                        # ───────────────────────────────
                        # Extract and link individual rules
                        # ───────────────────────────────
                        rules = getattr(spec, "rules", [])
                        for rule in rules:
                            rule_name = getattr(rule, "name", "unnamed-rule")
                            rule_type = "unknown"
                            if hasattr(rule, "validate"):
                                rule_type = "validate"
                            elif hasattr(rule, "mutate"):
                                rule_type = "mutate"
                            elif hasattr(rule, "generate"):
                                rule_type = "generate"

                            match = getattr(rule, "match", {})
                            exclude = getattr(rule, "exclude", {})
                            pattern = getattr(getattr(rule, "validate", {}), "pattern", None)
                            message = getattr(getattr(rule, "validate", {}), "message", None)
                            patch = getattr(getattr(rule, "mutate", {}), "patchStrategicMerge", None)

                            rule_risk_tags = []
                            if rule_type == "mutate":
                                rule_risk_tags.append("⚠️ mutates resources")
                            if rule_type == "generate":
                                rule_risk_tags.append("⚠️ generates resources")
                            if rule_type == "validate" and not pattern:
                                rule_risk_tags.append("⚠️ validate without pattern")

                            # Extract matched resources
                            match_kinds = []
                            try:
                                match_kinds = getattr(match["resources"], "kinds", [])
                            except Exception:
                                pass

                            if match_kinds and any(kind.lower() == "pod" for kind in match_kinds):
                                rule_risk_tags.append("⚠️ targets Pods")

                            try:
                                policyRuleNode = Node(
                                    "PolicyRule",
                                    name=rule_name,
                                    uid=f"{name}:{rule_name}",
                                    type=rule_type,
                                    message=message,
                                    matchKinds=str(match_kinds),
                                    pattern=str(pattern),
                                    patch=str(patch),
                                    exclude=str(exclude),
                                    risk=format_risk_tags(rule_risk_tags)
                                )
                                policyRuleNode.__primarylabel__ = "PolicyRule"
                                policyRuleNode.__primarykey__ = "uid"

                                tx = graph.begin()
                                tx.merge(policyRuleNode)
                                rel = Relationship(cpNode, "CONTAINS_RULE", policyRuleNode)
                                tx.merge(rel)
                                graph.commit(tx)

                            except Exception as e:
                                if release:
                                    print(e)
                                    pass
                                else:
                                    exc_type, exc_obj, exc_tb = sys.exc_info()
                                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                                    print(exc_type, fname, exc_tb.tb_lineno)
                                    print("Error:", e)
                                    sys.exit(1)

                    except Exception as e:
                        if release:
                            print(e)
                            pass
                        else:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            print(exc_type, fname, exc_tb.tb_lineno)
                            print("Error:", e)
                            sys.exit(1)

