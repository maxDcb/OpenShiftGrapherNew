import argparse
from argparse import RawTextHelpFormatter
import sys
import os
import re

import json
import subprocess

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from py2neo import Graph, Node, Relationship, NodeMatcher

import yaml
from kubernetes import client
from openshift.dynamic import DynamicClient
from openshift.helper.userpassauth import OCPLoginConfiguration

from progress.bar import Bar
 

def refresh_token():
    """Ask the user for a new token interactively."""
    print("\n⚠️  Your OpenShift API token has expired.")
    new_token = input("Please enter a new Bearer token: ").strip()
    if not new_token:
        raise ValueError("Token cannot be empty.")
    return new_token


def build_clients(api_key, hostApi, proxyUrl=None):
    kubeConfig = OCPLoginConfiguration(host=hostApi)
    kubeConfig.verify_ssl = False
    kubeConfig.token = api_key
    kubeConfig.api_key = {"authorization": f"Bearer {api_key}"}

    k8s_client = client.ApiClient(kubeConfig)

    if proxyUrl:
        proxyManager = urllib3.ProxyManager(proxyUrl)
        k8s_client.rest_client.pool_manager = proxyManager

    dyn_client = DynamicClient(k8s_client)
    v1 = client.CoreV1Api(k8s_client)
    return dyn_client, v1


def fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, api_version, kind):
    """
    Fetch a resource list from OpenShift with automatic token refresh on 401.

    Returns:
        (resource_list, dyn_client, api_key)
    """
    try:
        resource = dyn_client.resources.get(api_version=api_version, kind=kind)
        resource_list = resource.get()
        return resource_list, dyn_client, api_key
    except client.exceptions.ApiException as e:
        if e.status == 401:
            # Token expired → ask for a new one
            api_key = refresh_token()
            dyn_client, _ = build_clients(api_key, hostApi, proxyUrl)
            resource = dyn_client.resources.get(api_version=api_version, kind=kind)
            resource_list = resource.get()
            return resource_list, dyn_client, api_key
        else:
            print(f"[-] Error fetching {kind}: {e}")
            raise


def main():
    ##
    ## Input
    ##
    parser = argparse.ArgumentParser(description=f"""Exemple:
        OpenShiftGrapher -a "https://api.cluster.net:6443" -t "eyJhbGciOi..."
        OpenShiftGrapher -a "https://api.cluster.net:6443" -t $(cat token.txt) -c all -d customDB -u neo4j -p rootroot -r
        OpenShiftGrapher -a "https://api.cluster.net:6443" -t $(cat token.txt) -c scc role route""",
        formatter_class=RawTextHelpFormatter,)

    parser.add_argument('-r', '--resetDB', action="store_true", help='reset the neo4j db.')
    parser.add_argument('-a', '--apiUrl', required=True, help='api url.')
    parser.add_argument('-t', '--token', required=True, help='service account token.')
    parser.add_argument('-c', '--collector', nargs="+", default="all", help='list of collectors. Possible values: all, project, scc, sa, role, clusterrole, rolebinding, clusterrolebinding, route, pod, kyverno, validatingwebhookconfiguration, mutatingwebhookconfiguration, clusterpolicies')
    parser.add_argument('-u', '--userNeo4j', default="neo4j", help='neo4j database user.')
    parser.add_argument('-p', '--passwordNeo4j', default="rootroot", help='neo4j database password.')
    parser.add_argument('-x', '--proxyUrl', default="", help='proxy url.')
    parser.add_argument('-d', '--databaseName', default="neo4j", help='Database Name.')

    args = parser.parse_args()

    hostApi = args.apiUrl
    api_key = args.token
    resetDB = args.resetDB
    userNeo4j = args.userNeo4j
    passwordNeo4j = args.passwordNeo4j
    collector = args.collector
    proxyUrl = args.proxyUrl
    databaseName = args.databaseName

    release = True


    ##
    ## Init OC
    ##
    print("#### Init OC ####")
    
    dyn_client, v1 = build_clients(api_key, hostApi, proxyUrl)

    ##
    ## Init neo4j
    ##
    print("#### Init neo4j ####")

    graph = Graph("bolt://localhost:7687", name=databaseName, user=userNeo4j, password=passwordNeo4j)
    if resetDB:
        if input("are you sure your want to reset the db? (y/n)") != "y":
            exit()
        graph.delete_all()


    ##
    ## Perform all network calls first to avoid redoing them in case of token expiration
    ## 

    print("#### Fetch resources ####")

    print("Fetching OAuth")
    oauth_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, "config.openshift.io/v1", "OAuth")
    
    print("Fetching Identity")
    identity_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, "user.openshift.io/v1", "Identity")

    print("Fetching Projects")
    project_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, "project.openshift.io/v1", "Project")

    print("Fetching ServiceAccounts")
    serviceAccount_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, 'v1', 'ServiceAccount')

    print("Fetching SCC")
    SCC_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, 'security.openshift.io/v1', 'SecurityContextConstraints')

    print("Fetching Roles")
    role_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, 'rbac.authorization.k8s.io/v1', 'Role')

    print("Fetching ClusterRoles")
    clusterrole_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, 'rbac.authorization.k8s.io/v1', 'ClusterRole')

    print("Fetching Users")
    user_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, 'user.openshift.io/v1', 'User')

    print("Fetching Groups")
    group_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, 'user.openshift.io/v1', 'Group')

    print("Fetching RoleBindings")
    roleBinding_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, 'rbac.authorization.k8s.io/v1', 'RoleBinding')

    print("Fetching ClusterRoleBindings")
    clusterRoleBinding_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, 'rbac.authorization.k8s.io/v1', 'ClusterRoleBinding')

    print("Fetching Routes")
    route_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, 'route.openshift.io/v1', 'Route')

    print("Fetching Pods")
    pod_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, 'v1', 'Pod')

    print("Fetching Kyverno logs from pods")
    kyverno_logs = {}
    for enum in pod_list.items:
        name = enum.metadata.name
        namespace = enum.metadata.namespace
        uid = enum.metadata.uid

        if "kyverno-admission-controller" in name:
            try:
                # Use the dynamic client request for raw logs
                response = dyn_client.request(
                    "get",
                    f"/api/v1/namespaces/{namespace}/pods/{name}/log"
                )

                if isinstance(response, str):
                    log_text = response.strip()
                elif hasattr(response, "text"):
                    log_text = response.text.strip()
                else:
                    log_text = str(response).strip()

                # Get the log text
                kyverno_logs[uid] = log_text

            except Exception as e:
                print(f"[-] Failed to get logs for {name}: {e}")
                continue

    print("Fetching ConfigMaps")
    configmap_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, 'v1', 'ConfigMap')

    print("Fetching ValidatingWebhookConfigurations")
    validatingWebhookConfiguration_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, 'admissionregistration.k8s.io/v1', 'ValidatingWebhookConfiguration')

    print("Fetching MutatingWebhookConfiguration")
    mutatingWebhookConfiguration_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, "admissionregistration.k8s.io/v1", "MutatingWebhookConfiguration")

    print("Fetching ClusterPolicy")
    clusterPolicy_list, dyn_client, api_key = fetch_resource_with_refresh(dyn_client, api_key, hostApi, proxyUrl, "kyverno.io/v1", "ClusterPolicy")


    ##
    ## OAuth
    ##
    print("#### OAuth ####")

    if "all" in collector or "oauth" in collector:
        existing_count = graph.nodes.match("OAuth").count()
        if existing_count >= len(oauth_list.items):
            print(f"⚠️ Database already has {existing_count} OAuth nodes, skipping import.")
        else:
            with Bar('OAuth',max = len(oauth_list.items)) as bar:
                    for enum in oauth_list.items:
                        bar.next()

                        oauthNode = Node("OAuth", name=enum.metadata.name)
                        oauthNode.__primarylabel__ = "OAuth"
                        oauthNode.__primarykey__ = "name"

                        tx = graph.begin()
                        tx.merge(oauthNode)

                        for idp in getattr(enum.spec, "identityProviders", []):
                            idpNode = Node("IdentityProvider",
                                        name=idp.name,
                                        type=idp.type,
                                        mappingMethod=getattr(idp, "mappingMethod", "N/A"))
                            idpNode.__primarylabel__ = "IdentityProvider"
                            idpNode.__primarykey__ = "name"
                            tx.merge(idpNode)

                            rel = Relationship(oauthNode, "USES_PROVIDER", idpNode)
                            tx.merge(rel)
                        graph.commit(tx)


    ##
    ## Identities
    ##
    print("#### Identities ####")

    if "all" in collector or "identity" in collector:
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
                    identityNode = Node(
                        "Identity",
                        name=name,
                        provider=provider_name,
                        providerUser=provider_user,
                        linkedUser=linked_user
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


    ##
    ## Project
    ##
    print("#### Project ####")    

    if "all" in collector or "project" in collector:
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
                            annotations=str(annotations)  # keep full annotations dict as string
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


    ##
    ## Service account
    ##
    print("#### Service Account ####")

    if "all" in collector or "sa" in collector or "serviceaccount" in collector:
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
                            labels=str(labels)
                        )
                        a.__primarylabel__ = "ServiceAccount"
                        a.__primarykey__ = "uid"

                        target_project = next(
                            (p for p in project_list.items if p.metadata.name == enum.metadata.namespace),
                            None
                        )

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


    ##
    ## SCC
    ##
    print("#### SCC ####")

    if "all" in collector or "scc" in collector:
        existing_count = graph.nodes.match("SCC").count()
        if existing_count >= len(SCC_list.items):
            print("⚠️ SCC graph up-to-date, skipping import.")
        else:
            with Bar('SCC',max = len(SCC_list.items)) as bar:
                for scc in SCC_list.items:
                    bar.next()

                    try:
                        isPriv = scc.allowPrivilegedContainer

                        tx = graph.begin()
                        sccNode = Node("SCC",name=scc.metadata.name, 
                            uid=scc.metadata.uid, 
                            allowPrivilegeEscalation=scc.allowPrivilegedContainer,
                            allowHostNetwork=scc.allowHostNetwork,
                            allowHostPID=scc.allowHostPID,
                            allowHostIPC=scc.allowHostIPC,
                            priority=scc.priority if hasattr(scc, "priority") else None,
                        )
                        sccNode.__primarylabel__ = "SCC"
                        sccNode.__primarykey__ = "uid"
                        node = tx.merge(sccNode) 
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
                                    target_group = next(
                                        (g for g in group_list.items if g.metadata.name == group),
                                        None
                                    )
                                    
                                    groupNode = Node("Group", name=target_group.metadata.name, uid=target_group.metadata.uid)
                                    groupNode.__primarylabel__ = "Group"
                                    groupNode.__primarykey__ = "uid"

                                # Create the SCC -> Group relationship
                                tx = graph.begin()
                                r = Relationship(groupNode, "CAN USE SCC", sccNode)
                                tx.merge(groupNode)
                                tx.merge(sccNode)
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


                    if hasattr(scc, "users") and scc.groups:
                        for subject in scc.users:
                            split = subject.split(":")
                            if len(split)==4:
                                if "serviceaccount" ==  split[1]:
                                    subjectNamespace = split[2]
                                    subjectName = split[3]

                                    if subjectNamespace:
                                        try:
                                            target_project = next(
                                                (p for p in project_list.items if p.metadata.name == subjectNamespace),
                                                None
                                            )
                                            projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                                            projectNode.__primarylabel__ = "Project"
                                            projectNode.__primarykey__ = "uid"

                                        except: 
                                            projectNode = Node("AbsentProject", name=subjectNamespace, uid=subjectNamespace)
                                            projectNode.__primarylabel__ = "AbsentProject"
                                            projectNode.__primarykey__ = "uid"

                                        try:
                                            target_sa = next(
                                                (sa for sa in serviceAccount_list.items
                                                if sa.metadata.name == subjectName
                                                and sa.metadata.namespace == subjectNamespace),
                                                None
                                            )
                                            subjectNode = Node("ServiceAccount",name=target_sa.metadata.name, namespace=target_sa.metadata.namespace, uid=target_sa.metadata.uid)
                                            subjectNode.__primarylabel__ = "ServiceAccount"
                                            subjectNode.__primarykey__ = "uid"

                                        except: 
                                            subjectNode = Node("AbsentServiceAccount", name=subjectName, namespace=subjectNamespace, uid=subjectName+"_"+subjectNamespace)
                                            subjectNode.__primarylabel__ = "AbsentServiceAccount"
                                            subjectNode.__primarykey__ = "uid"

                                        try:
                                            tx = graph.begin()
                                            r1 = Relationship(projectNode, "CONTAIN SA", subjectNode)
                                            r2 = Relationship(subjectNode, "CAN USE SCC", sccNode)
                                            node = tx.merge(projectNode) 
                                            node = tx.merge(subjectNode) 
                                            node = tx.merge(sccNode) 
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


    ##
    ## Role
    ## 
    print("#### Role ####")

    if "all" in collector or "role" in collector:
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
                        privileged_keywords = [
                            "pods/exec", "pods/attach", "secrets", "configmaps",
                            "pods/portforward", "serviceaccounts", "securitycontextconstraints"
                        ]
                        dangerous_verbs = ["create", "update", "patch", "delete", "*"]
                        risk_flag = "✅ normal"

                        for rule in getattr(role, "rules", []) or []:
                            verbs = getattr(rule, "verbs", []) or []
                            resources = getattr(rule, "resources", []) or []
                            for v in verbs:
                                for r in resources:
                                    if any(dv in v for dv in dangerous_verbs) and any(pk in r for pk in privileged_keywords):
                                        risk_flag = "⚠️ potential privilege escalation"
                                        break

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
                            risk=risk_flag
                        )
                        roleNode.__primarylabel__ = "Role"
                        roleNode.__primarykey__ = "uid"
                        tx.merge(roleNode)

                        # ───────────────────────────────
                        # Link Role → Project
                        # ───────────────────────────────
                        target_project = next(
                            (p for p in project_list.items if p.metadata.name == namespace),
                            None
                        )
                        if target_project:
                            projectNode = Node("Project",
                                            name=target_project.metadata.name,
                                            uid=target_project.metadata.uid)
                            projectNode.__primarylabel__ = "Project"
                            projectNode.__primarykey__ = "uid"
                        else:
                            projectNode = Node("AbsentProject", name=subjectNamespace, uid=subjectNamespace)
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

                            # Handle SCCs explicitly
                            for apiGroup in apiGroups:
                                for resource in resources:
                                    if resource == "securitycontextconstraints":
                                        for resourceName in getattr(rule, "resourceNames", []) or []:
                                            try:
                                                target_scc = next(
                                                    (s for s in SCC_list.items if s.metadata.name == resourceName),
                                                    None
                                                )
                                                if target_scc:
                                                    sccNode = Node("SCC",
                                                                name=target_scc.metadata.name,
                                                                uid=target_scc.metadata.uid,
                                                                exists=True)
                                                else:
                                                    raise ValueError("AbsentSCC")

                                            except:
                                                sccNode = Node("AbsentSCC",
                                                            name=resourceName,
                                                            uid=f"SCC_{resourceName}",
                                                            exists=False)

                                            sccNode.__primarylabel__ = "SCC"
                                            sccNode.__primarykey__ = "uid"
                                            tx.merge(sccNode)
                                            tx.merge(Relationship(roleNode, "CAN_USE_SCC", sccNode))

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


    ##
    ## ClusterRole
    ## 
    print("#### ClusterRole ####")

    if "all" in collector or "clusterrole" in collector:
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
                        privileged_keywords = [
                            "pods/exec", "pods/attach", "secrets", "configmaps",
                            "pods/portforward", "serviceaccounts", "securitycontextconstraints"
                        ]
                        dangerous_verbs = ["create", "update", "patch", "delete", "*"]
                        risk_flag = "✅ normal"

                        for rule in getattr(role, "rules", []) or []:
                            verbs = getattr(rule, "verbs", []) or []
                            resources = getattr(rule, "resources", []) or []
                            for v in verbs:
                                for r in resources:
                                    if any(dv in v for dv in dangerous_verbs) and any(pk in r for pk in privileged_keywords):
                                        risk_flag = "⚠️ potential privilege escalation"
                                        break

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
                            risk=risk_flag
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

                            # Handle SCCs explicitly
                            for apiGroup in apiGroups:
                                for resource in resources:
                                    if resource == "securitycontextconstraints":
                                        for resourceName in getattr(rule, "resourceNames", []) or []:
                                            try:
                                                target_scc = next(
                                                    (s for s in SCC_list.items if s.metadata.name == resourceName),
                                                    None
                                                )
                                                if target_scc:
                                                    sccNode = Node(
                                                        "SCC",
                                                        name=target_scc.metadata.name,
                                                        uid=target_scc.metadata.uid,
                                                        exists=True
                                                    )
                                                else:
                                                    raise ValueError("AbsentSCC")

                                            except:
                                                sccNode = Node(
                                                    "AbsentSCC",
                                                    name=resourceName,
                                                    uid=f"SCC_{resourceName}",
                                                    exists=False
                                                )

                                            sccNode.__primarylabel__ = "SCC"
                                            sccNode.__primarykey__ = "uid"
                                            tx.merge(sccNode)
                                            tx.merge(Relationship(roleNode, "CAN_USE_SCC", sccNode))

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


    ##
    ## User
    ## 
    print("#### User ####")

    if "all" in collector or "user" in collector:
        existing_count = graph.nodes.match("User").count()
        if existing_count >= len(user_list.items):
            print(f"⚠️ Database already has {existing_count} User nodes, skipping import.")
        else:
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
                        if name.startswith("system:"):
                            risk_flag = "⚠️ system account"
                        elif name in ["kube:admin", "admin"]:
                            risk_flag = "⚠️ cluster administrator"
                        else:
                            risk_flag = "✅ normal"

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
                            risk=risk_flag
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


    ##
    ## Group
    ## 
    print("#### Group ####")

    if "all" in collector or "group" in collector:
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
                        if name.startswith("system:authenticated"):
                            risk_flag = "⚠️ all authenticated users"
                        elif name.startswith("system:unauthenticated"):
                            risk_flag = "⚠️ unauthenticated group"
                        elif name.startswith("system:"):
                            risk_flag = "⚠️ system group"
                        else:
                            risk_flag = "✅ normal"

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
                            risk=risk_flag
                        )
                        groupNode.__primarylabel__ = "Group"
                        groupNode.__primarykey__ = "uid"
                        tx.merge(groupNode)

                        # ───────────────────────────────
                        # Link Group → Users
                        # ───────────────────────────────
                        for user_name in users:
                            try:
                                target_user = next(
                                    (u for u in user_list.items if u.metadata.name == user_name),
                                    None
                                )
                                if target_user:
                                    userNode = Node(
                                        "User",
                                        name=target_user.metadata.name,
                                        uid=target_user.metadata.uid
                                    )
                                else:
                                    raise ValueError("AbsentUser")
                            except:
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


    ##
    ## RoleBinding
    ## 
    print("#### RoleBinding ####")

    if "all" in collector or "rolebinding" in collector:
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

                    rolebindingNode = Node("RoleBinding", name=name, namespace=namespace, uid=enum.metadata.uid)
                    rolebindingNode.__primarylabel__ = "RoleBinding"
                    rolebindingNode.__primarykey__ = "uid"

                    roleKind = enum.roleRef.kind
                    roleName = enum.roleRef.name

                    if roleKind == "ClusterRole":
                        try:                            
                            target_clusterroles = next(
                                (p for p in clusterrole_list.items if p.metadata.name == roleName),
                                None
                            )
                            roleNode = Node("ClusterRole",name=target_clusterroles.metadata.name, uid=target_clusterroles.metadata.uid)
                            roleNode.__primarylabel__ = "ClusterRole"
                            roleNode.__primarykey__ = "uid"

                        except: 
                            roleNode = Node("AbsentClusterRole", name=roleName, uid=roleName)
                            roleNode.__primarylabel__ = "AbsentClusterRole"
                            roleNode.__primarykey__ = "uid"

                    elif roleKind == "Role":
                        try:
                            target_role = next(
                                (
                                    r for r in role_list.items
                                    if r.metadata.name == roleName and r.metadata.namespace == enum.metadata.namespace
                                ),
                                None
                            )
                            roleNode = Node("Role",name=target_role.metadata.name, namespace=target_role.metadata.namespace, uid=target_role.metadata.uid)
                            roleNode.__primarylabel__ = "Role"
                            roleNode.__primarykey__ = "uid"

                        except: 
                            roleNode = Node("AbsentRole",name=roleName, namespace=namespace, uid=roleName + "_" + namespace)
                            roleNode.__primarylabel__ = "AbsentRole"
                            roleNode.__primarykey__ = "uid"

                    if enum.subjects:
                        for subject in enum.subjects:
                            subjectKind = subject.kind
                            subjectName = subject.name
                            subjectNamespace = subject.namespace

                            if not subjectNamespace:
                                subjectNamespace = namespace

                            if subjectKind == "ServiceAccount": 
                                if subjectNamespace:
                                    try:
                                        target_project = next(
                                            (p for p in project_list.items if p.metadata.name == subjectNamespace),
                                            None
                                        )
                                        projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                                        projectNode.__primarylabel__ = "Project"
                                        projectNode.__primarykey__ = "uid"

                                    except: 
                                        projectNode = Node("AbsentProject", name=subjectNamespace, uid=subjectNamespace)
                                        projectNode.__primarylabel__ = "AbsentProject"
                                        projectNode.__primarykey__ = "uid"

                                    try:
                                        target_sa = next(
                                            (sa for sa in serviceAccount_list.items
                                            if sa.metadata.name == subjectName
                                            and sa.metadata.namespace == subjectNamespace),
                                            None
                                        )
                                        subjectNode = Node("ServiceAccount",name=target_sa.metadata.name, namespace=target_sa.metadata.namespace, uid=target_sa.metadata.uid)
                                        subjectNode.__primarylabel__ = "ServiceAccount"
                                        subjectNode.__primarykey__ = "uid"

                                    except: 
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

                                    try:
                                        target_project = next(
                                            (p for p in project_list.items if p.metadata.name == groupNamespace),
                                            None
                                        )
                                        groupNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                                        groupNode.__primarylabel__ = "Project"
                                        groupNode.__primarykey__ = "uid"

                                    except: 
                                        groupNode = Node("AbsentProject", name=groupNamespace, uid=groupNamespace)
                                        groupNode.__primarylabel__ = "AbsentProject"
                                        groupNode.__primarykey__ = "uid"

                                elif "system:" in subjectName:
                                    groupNode = Node("SystemGroup", name=subjectName, uid=subjectName)
                                    groupNode.__primarylabel__ = "SystemGroup"
                                    groupNode.__primarykey__ = "uid"

                                else:
                                    try:
                                        target_group = next(
                                            (g for g in group_list.items if g.metadata.name == subjectName),
                                            None
                                        )
                                        groupNode = Node("Group", name=target_group.metadata.name, uid=target_group.metadata.uid)
                                        groupNode.__primarylabel__ = "Group"
                                        groupNode.__primarykey__ = "uid"

                                    except: 
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

                                try:
                                    target_user = next(
                                        (p for p in user_list.items if p.metadata.name == subjectName),
                                        None
                                    )
                                    userNode = Node("User", name=target_user.metadata.name, uid=target_user.metadata.uid)
                                    userNode.__primarylabel__ = "User"
                                    userNode.__primarykey__ = "uid"

                                except: 
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
                                    

    ##
    ## ClusterRoleBinding
    ## 
    print("#### ClusterRoleBinding ####")

    if "all" in collector or "clusterrolebinding" in collector:
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

                    clusterRolebindingNode = Node("ClusterRoleBinding", name=name, namespace=namespace, uid=uid)
                    clusterRolebindingNode.__primarylabel__ = "ClusterRoleBinding"
                    clusterRolebindingNode.__primarykey__ = "uid"

                    roleKind = enum.roleRef.kind
                    roleName = enum.roleRef.name

                    if roleKind == "ClusterRole":
                        try:
                            target_clusterroles = next(
                                (p for p in clusterrole_list.items if p.metadata.name == roleName),
                                None
                            )
                            roleNode = Node("ClusterRole",name=target_clusterroles.metadata.name, uid=target_clusterroles.metadata.uid)
                            roleNode.__primarylabel__ = "ClusterRole"
                            roleNode.__primarykey__ = "uid"

                        except: 
                            roleNode = Node("AbsentClusterRole",name=roleName, uid=roleName)
                            roleNode.__primarylabel__ = "AbsentClusterRole"
                            roleNode.__primarykey__ = "uid"

                    elif roleKind == "Role":
                        try:
                            target_role = next(
                                (
                                    r for r in role_list.items
                                    if r.metadata.name == roleName and r.metadata.namespace == enum.metadata.namespace
                                ),
                                None
                            )
                            roleNode = Node("Role",name=target_role.metadata.name, namespace=target_role.metadata.namespace, uid=target_role.metadata.uid)
                            roleNode.__primarylabel__ = "Role"
                            roleNode.__primarykey__ = "uid"

                        except: 
                            roleNode = Node("AbsentRole",name=roleName, namespace=namespace, uid=roleName+"_"+namespace)
                            roleNode.__primarylabel__ = "AbsentRole"
                            roleNode.__primarykey__ = "uid"

                    if enum.subjects:
                        for subject in enum.subjects:
                            subjectKind = subject.kind
                            subjectName = subject.name
                            subjectNamespace = subject.namespace

                            if subjectKind == "ServiceAccount": 
                                if subjectNamespace:
                                    try:
                                        target_project = next(
                                            (p for p in project_list.items if p.metadata.name == subjectNamespace),
                                            None
                                        )
                                        projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                                        projectNode.__primarylabel__ = "Project"
                                        projectNode.__primarykey__ = "uid"

                                    except: 
                                        projectNode = Node("AbsentProject", name=subjectNamespace, uid=subjectNamespace)
                                        projectNode.__primarylabel__ = "AbsentProject"
                                        projectNode.__primarykey__ = "uid"

                                    try:
                                        target_sa = next(
                                            (sa for sa in serviceAccount_list.items
                                            if sa.metadata.name == subjectName
                                            and sa.metadata.namespace == subjectNamespace),
                                            None
                                        )
                                        subjectNode = Node("ServiceAccount",name=target_sa.metadata.name, namespace=target_sa.metadata.namespace, uid=target_sa.metadata.uid)
                                        subjectNode.__primarylabel__ = "ServiceAccount"
                                        subjectNode.__primarykey__ = "uid"

                                    except: 
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

                                    try:
                                        target_project = next(
                                            (p for p in project_list.items if p.metadata.name == groupNamespace),
                                            None
                                        )
                                        groupNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                                        groupNode.__primarylabel__ = "Project"
                                        groupNode.__primarykey__ = "uid"

                                    except: 
                                        groupNode = Node("AbsentProject", name=groupNamespace, uid=groupNamespace)
                                        groupNode.__primarylabel__ = "AbsentProject"
                                        groupNode.__primarykey__ = "uid"

                                elif "system:" in subjectName:
                                    groupNode = Node("SystemGroup", name=subjectName, uid=subjectName)
                                    groupNode.__primarylabel__ = "SystemGroup"
                                    groupNode.__primarykey__ = "uid"

                                else:
                                    try:
                                        target_group = next(
                                            (g for g in group_list.items if g.metadata.name == subjectName),
                                            None
                                        )
                                        groupNode = Node("Group", name=target_group.metadata.name, uid=target_group.metadata.uid)
                                        groupNode.__primarylabel__ = "Group"
                                        groupNode.__primarykey__ = "uid"

                                    except: 
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

                                try:
                                    target_user = next(
                                        (p for p in user_list.items if p.metadata.name == subjectName),
                                        None
                                    )
                                    userNode = Node("User", name=target_user.metadata.name, uid=target_user.metadata.uid)
                                    userNode.__primarylabel__ = "User"
                                    userNode.__primarykey__ = "uid"

                                except: 
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


    ##
    ## Route
    ## 
    print("#### Route ####")

    if "all" in collector or "route" in collector:
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
                    target_project = next(
                        (p for p in project_list.items if p.metadata.name == namespace),
                        None
                    )
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


    ##
    ## Pod
    ## 
    print("#### Pod ####")

    if "all" in collector or "pod" in collector:
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

                    try:
                        target_project = next(
                            (p for p in project_list.items if p.metadata.name == namespace),
                            None
                        )
                        projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                        projectNode.__primarylabel__ = "Project"
                        projectNode.__primarykey__ = "uid"

                    except: 
                        projectNode = Node("AbsentProject",name=namespace)
                        projectNode.__primarylabel__ = "AbsentProject"
                        projectNode.__primarykey__ = "name"

                    podNode = Node("Pod",name=name, namespace=namespace, uid=uid)
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


    ##
    ## ConfigMap
    ## 
    print("#### ConfigMap ####")

    if "all" in collector or "configmap" in collector:
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

                    try:
                        target_project = next(
                            (p for p in project_list.items if p.metadata.name == namespace),
                            None
                        )
                        projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                        projectNode.__primarylabel__ = "Project"
                        projectNode.__primarykey__ = "uid"

                    except: 
                        projectNode = Node("AbsentProject",name=namespace)
                        projectNode.__primarylabel__ = "AbsentProject"
                        projectNode.__primarykey__ = "name"

                    configmapNode = Node("ConfigMap",name=name, namespace=namespace, uid=uid)
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


    ##
    ## Kyverno 
    ## 
    print("#### Kyverno ####")

    if "all" in collector or "kyverno" in collector:
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
                                    try:
                                        target_project = next(
                                            (p for p in project_list.items if p.metadata.name == subjectNamespace),
                                            None
                                        )
                                        projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                                        projectNode.__primarylabel__ = "Project"
                                        projectNode.__primarykey__ = "uid"

                                    except: 
                                        projectNode = Node("AbsentProject", name=subjectNamespace, uid=subjectNamespace)
                                        projectNode.__primarylabel__ = "AbsentProject"
                                        projectNode.__primarykey__ = "uid"

                                    try:
                                        target_sa = next(
                                            (sa for sa in serviceAccount_list.items
                                            if sa.metadata.name == subjectName
                                            and sa.metadata.namespace == subjectNamespace),
                                            None
                                        )
                                        subjectNode = Node("ServiceAccount",name=target_sa.metadata.name, namespace=target_sa.metadata.namespace, uid=target_sa.metadata.uid)
                                        subjectNode.__primarylabel__ = "ServiceAccount"
                                        subjectNode.__primarykey__ = "uid"

                                    except: 
                                        subjectNode = Node("AbsentServiceAccount", name=subjectName, namespace=subjectNamespace, uid=subjectName+"_"+subjectNamespace)
                                        subjectNode.__primarylabel__ = "AbsentServiceAccount"
                                        subjectNode.__primarykey__ = "uid"

                                    try:
                                        kyvernoWhitelistNode = Node("KyvernoWhitelist", name="KyvernoWhitelist", uid="KyvernoWhitelist")
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

            
    ##
    ## ValidatingWebhookConfiguration 
    ## 
    print("#### ValidatingWebhookConfiguration ####")

    if "all" in collector or "validatingwebhookconfiguration" in collector:
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
                    cfgNode = Node(
                        "ValidatingWebhookConfiguration",
                        name=config_name,
                        uid=getattr(enum.metadata, "uid", config_name)
                    )
                    cfgNode.__primarylabel__ = "ValidatingWebhookConfiguration"
                    cfgNode.__primarykey__ = "uid"

                    tx = graph.begin()
                    tx.merge(cfgNode)
                    graph.commit(tx)

                    # ───────────────────────────────
                    # Handle each webhook under it
                    # ───────────────────────────────
                    webhooks = getattr(enum, "webhooks", [])
                    for webhook in webhooks:
                        webhook_name = getattr(webhook, "name", "unknown-webhook")

                        # Core webhook properties
                        failure_policy = getattr(webhook, "failurePolicy", None)
                        side_effects = getattr(webhook, "sideEffects", None)
                        timeout = getattr(webhook, "timeoutSeconds", None)
                        admission_review_versions = getattr(webhook, "admissionReviewVersions", None)
                        rules = getattr(webhook, "rules", [])
                        client_config = getattr(webhook, "clientConfig", None)

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
                            apis = getattr(rule, "apiGroups", [])
                            resources = getattr(rule, "resources", [])
                            verbs = getattr(rule, "verbs", [])
                            rule_summaries.append(f"APIs={apis} RES={resources} VERBS={verbs}")
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


    ##
    ## MutatingWebhookConfiguration 
    ## 
    print("#### MutatingWebhookConfiguration ####")

    if "all" in collector or "mutatingwebhookconfiguration" in collector:
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
                    cfgNode = Node(
                        "MutatingWebhookConfiguration",
                        name=config_name,
                        uid=getattr(enum.metadata, "uid", config_name),
                    )
                    cfgNode.__primarylabel__ = "MutatingWebhookConfiguration"
                    cfgNode.__primarykey__ = "uid"

                    tx = graph.begin()
                    tx.merge(cfgNode)
                    graph.commit(tx)

                    # ───────────────────────────────
                    # Iterate through webhooks
                    # ───────────────────────────────
                    webhooks = getattr(enum, "webhooks", [])
                    for webhook in webhooks:
                        webhook_name = getattr(webhook, "name", "unknown-webhook")
                        failure_policy = getattr(webhook, "failurePolicy", None)
                        side_effects = getattr(webhook, "sideEffects", None)
                        timeout = getattr(webhook, "timeoutSeconds", None)
                        admission_review_versions = getattr(webhook, "admissionReviewVersions", None)
                        reinvocation_policy = getattr(webhook, "reinvocationPolicy", None)
                        match_policy = getattr(webhook, "matchPolicy", None)

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


    ##
    ## ClusterPolicy 
    ## 
    print("#### ClusterPolicy ####")

    if "all" in collector or "clusterpolicies" in collector:
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

                    try:
                        # Create ClusterPolicy node
                        cpNode = Node(
                            "ClusterPolicy",
                            name=name,
                            uid=getattr(enum.metadata, "uid", name),
                            enforcement=enforcement,
                            background=background,
                            overrides=str(validationFailureActionOverrides),
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

                            # Extract matched resources
                            match_kinds = []
                            try:
                                match_kinds = getattr(match["resources"], "kinds", [])
                            except Exception:
                                pass

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


if __name__ == '__main__':
    main()