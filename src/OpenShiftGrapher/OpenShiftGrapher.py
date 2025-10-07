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
        OpenShiftGrapher -a "https://api.cluster.net:6443" -t $(cat token.txt)
        OpenShiftGrapher -a "https://api.cluster.net:6443" -t $(cat token.txt) -c scc role route""",
        formatter_class=RawTextHelpFormatter,)

    parser.add_argument('-r', '--resetDB', action="store_true", help='reset the neo4j db.')
    parser.add_argument('-a', '--apiUrl', required=True, help='api url.')
    parser.add_argument('-t', '--token', required=True, help='service account token.')
    parser.add_argument('-c', '--collector', nargs="+", default="all", help='list of collectors. Possible values: all, project, scc, sa, role, clusterrole, rolebinding, clusterrolebinding, route, pod ')
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

    ##
    ## Project
    ##
    print("#### Project ####")    

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("Project").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} Project nodes, skipping import.")
    else:
        if "all" in collector or "project" in collector:
            with Bar('Project',max = len(project_list.items)) as bar:
                for enum in project_list.items:
                    bar.next()
                    # print(enum.metadata)
                    try:
                        tx = graph.begin()
                        a = Node("Project", name=enum.metadata.name, uid=enum.metadata.uid)
                        a.__primarylabel__ = "Project"
                        a.__primarykey__ = "uid"
                        node = tx.merge(a) 
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
    
    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("ServiceAccount").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} ServiceAccount nodes, skipping import.")
    else:
        if "all" in collector or "sa" in collector:
            with Bar('Service Account',max = len(serviceAccount_list.items)) as bar:
                for enum in serviceAccount_list.items:
                    bar.next()
                    # print(enum.metadata)
                    try:
                        tx = graph.begin()
                        a = Node("ServiceAccount", name=enum.metadata.name, namespace=enum.metadata.namespace, uid=enum.metadata.uid)
                        a.__primarylabel__ = "ServiceAccount"
                        a.__primarykey__ = "uid"

                        try:
                            target_project = next(
                                (p for p in project_list.items if p.metadata.name == enum.metadata.namespace),
                                None
                            )
                            projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                            projectNode.__primarylabel__ = "Project"
                            projectNode.__primarykey__ = "uid"

                        except: 
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


    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("SCC").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} SCC nodes, skipping import.")
    else:
        if "all" in collector or "scc" in collector:
            with Bar('SCC',max = len(SCC_list.items)) as bar:
                for scc in SCC_list.items:
                    bar.next()

                    try:
                        isPriv = scc.allowPrivilegedContainer

                        tx = graph.begin()
                        sccNode = Node("SCC",name=scc.metadata.name, uid=scc.metadata.uid, allowPrivilegeEscalation=isPriv)
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

                    userNames = scc.users
                    if userNames:
                        for subject in userNames:
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

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("Role").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} Role nodes, skipping import.")
    else:
        if "all" in collector or "role" in collector:
            with Bar('Role',max = len(role_list.items)) as bar:
                for role in role_list.items:
                    bar.next()
                    # print(role.metadata)

                    roleNode = Node("Role",name=role.metadata.name, namespace=role.metadata.namespace, uid=role.metadata.uid)
                    roleNode.__primarylabel__ = "Role"
                    roleNode.__primarykey__ = "uid"

                    try:
                        tx = graph.begin()
                        node = tx.merge(roleNode) 
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

                    if role.rules:
                        for rule in role.rules:
                            if rule.apiGroups:
                                for apiGroup in rule.apiGroups:
                                    for resource in rule.resources:
                                        if resource == "securitycontextconstraints":
                                            if rule.resourceNames:
                                                for resourceName in rule.resourceNames:

                                                    try:
                                                        target_scc = next(
                                                            (s for s in SCC_list.items if s.metadata.name == resourceName),
                                                            None
                                                        )
                                                        sccNode = Node("SCC", name=target_scc.metadata.name, uid=target_scc.metadata.uid)
                                                        sccNode.__primarylabel__ = "SCC"
                                                        sccNode.__primarykey__ = "uid"
                                                    except: 
                                                        sccNode = Node("AbsentSCC", name=resourceName, uid="SCC_"+resourceName)
                                                        sccNode.__primarylabel__ = "AbsentSCC"
                                                        sccNode.__primarykey__ = "uid"

                                                    try:
                                                        tx = graph.begin()
                                                        r1 = Relationship(roleNode, "CAN USE SCC", sccNode)
                                                        node = tx.merge(roleNode) 
                                                        node = tx.merge(sccNode) 
                                                        node = tx.merge(r1) 
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
                                            for verb in rule.verbs:

                                                if apiGroup == "":
                                                    resourceName = resource
                                                else:
                                                    resourceName = f"{apiGroup}:{resource}"

                                                ressourceNode = Node("Resource", name=resourceName, uid="Resource_"+role.metadata.namespace+"_"+resourceName)
                                                ressourceNode.__primarylabel__ = "Resource"
                                                ressourceNode.__primarykey__ = "uid"

                                                try:
                                                    tx = graph.begin()
                                                    if verb == "impersonate":
                                                        r1 = Relationship(roleNode, "impers", ressourceNode)  
                                                    else:
                                                        r1 = Relationship(roleNode, verb, ressourceNode)
                                                    node = tx.merge(roleNode) 
                                                    node = tx.merge(ressourceNode) 
                                                    node = tx.merge(r1) 
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

                            if rule.nonResourceURLs: 
                                for nonResourceURL in rule.nonResourceURLs: 
                                    for verb in rule.verbs:

                                        ressourceNode = Node("ResourceNoUrl", name=nonResourceURL, uid="ResourceNoUrl_"+role.metadata.namespace+"_"+nonResourceURL)
                                        ressourceNode.__primarylabel__ = "ResourceNoUrl"
                                        ressourceNode.__primarykey__ = "uid"

                                        try:
                                            tx = graph.begin()
                                            r1 = Relationship(roleNode, verb, ressourceNode)
                                            node = tx.merge(roleNode) 
                                            node = tx.merge(ressourceNode) 
                                            node = tx.merge(r1) 
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
    ## ClusterRole
    ## 
    print("#### ClusterRole ####")

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("ClusterRole").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} ClusterRole nodes, skipping import.")
    else:
        if "all" in collector or "clusterrole" in collector:
            with Bar('ClusterRole',max = len(clusterrole_list.items)) as bar:
                for role in clusterrole_list.items:
                    bar.next()

                    try:
                        tx = graph.begin()
                        roleNode = Node("ClusterRole", name=role.metadata.name, uid=role.metadata.uid)
                        roleNode.__primarylabel__ = "ClusterRole"
                        roleNode.__primarykey__ = "uid"
                        node = tx.merge(roleNode) 
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

                    if role.rules:
                        for rule in role.rules:
                            if rule.apiGroups:
                                for apiGroup in rule.apiGroups:
                                    for resource in rule.resources:
                                        if resource == "securitycontextconstraints":
                                            if rule.resourceNames:
                                                for resourceName in rule.resourceNames:

                                                    try:
                                                        target_scc = next(
                                                            (s for s in SCC_list.items if s.metadata.name == resourceName),
                                                            None
                                                        )
                                                        sccNode = Node("SCC", name=target_scc.metadata.name, uid=target_scc.metadata.uid)
                                                        sccNode.__primarylabel__ = "SCC"
                                                        sccNode.__primarykey__ = "uid"
                                                    except: 
                                                        sccNode = Node("AbsentSCC", name=resourceName, uid="SCC_"+resourceName)
                                                        sccNode.__primarylabel__ = "AbsentSCC"
                                                        sccNode.__primarykey__ = "uid"

                                                    try:
                                                        tx = graph.begin()
                                                        r1 = Relationship(roleNode, "CAN USE SCC", sccNode)
                                                        node = tx.merge(roleNode) 
                                                        node = tx.merge(sccNode) 
                                                        node = tx.merge(r1) 
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
                                            for verb in rule.verbs:

                                                if apiGroup == "":
                                                    resourceName = resource
                                                else:
                                                    resourceName = f"{apiGroup}:{resource}"

                                                ressourceNode = Node("Resource", name=resourceName, uid="Resource_cluster"+"_"+resourceName)
                                                ressourceNode.__primarylabel__ = "Resource"
                                                ressourceNode.__primarykey__ = "uid"

                                                try:
                                                    tx = graph.begin()
                                                    if verb == "impersonate":
                                                        r1 = Relationship(roleNode, "impers", ressourceNode)  
                                                    else:
                                                        r1 = Relationship(roleNode, verb, ressourceNode)
                                                    node = tx.merge(roleNode) 
                                                    node = tx.merge(ressourceNode) 
                                                    node = tx.merge(r1) 
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

                            if rule.nonResourceURLs: 
                                for nonResourceURL in rule.nonResourceURLs: 
                                    for verb in rule.verbs:

                                        ressourceNode = Node("ResourceNoUrl", name=nonResourceURL, uid="ResourceNoUrl_cluster"+"_"+nonResourceURL)
                                        ressourceNode.__primarylabel__ = "ResourceNoUrl"
                                        ressourceNode.__primarykey__ = "uid"

                                        try:
                                            tx = graph.begin()
                                            r1 = Relationship(roleNode, verb, ressourceNode)
                                            node = tx.merge(roleNode) 
                                            node = tx.merge(ressourceNode) 
                                            node = tx.merge(r1) 
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
    ## User
    ## 
    print("#### User ####")

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("User").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} User nodes, skipping import.")
    else:
        if "all" in collector or "user" in collector:
            with Bar('User',max = len(user_list.items)) as bar:
                for enum in user_list.items:
                    bar.next()

                    name = enum.metadata.name
                    uid = enum.metadata.uid

                    userNode = Node("User", name=name, uid=uid)
                    userNode.__primarylabel__ = "User"
                    userNode.__primarykey__ = "uid"

                    try:
                        tx = graph.begin()
                        node = tx.merge(userNode) 
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
    ## Group
    ## 
    print("#### Group ####")

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("Group").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} Group nodes, skipping import.")
    else:
        if "all" in collector or "group" in collector:
            with Bar('Group',max = len(group_list.items)) as bar:
                for enum in group_list.items:
                    bar.next()

                    if enum.users:
                        for user in enum.users:
                            groupNode = Node("Group", name=enum.metadata.name, uid=enum.metadata.uid)
                            groupNode.__primarylabel__ = "Group"
                            groupNode.__primarykey__ = "uid"

                            try:
                                target_user = next(
                                    (p for p in user_list.items if p.metadata.name == user),
                                    None
                                )
                                # print(target_user)
                                userNode = Node("User", name=target_user.metadata.name, uid=target_user.metadata.uid)
                                userNode.__primarylabel__ = "User"
                                userNode.__primarykey__ = "uid"
                            except: 
                                userNode = Node("AbsentUser", name=user, uid=user)
                                userNode.__primarylabel__ = "AbsentUser"
                                userNode.__primarykey__ = "uid"
                            
                            try:
                                tx = graph.begin()
                                r1 = Relationship(groupNode, "CONTAIN USER", userNode)
                                node = tx.merge(groupNode) 
                                node = tx.merge(userNode) 
                                node = tx.merge(r1) 
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
    ## RoleBinding
    ## 
    print("#### RoleBinding ####")

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("RoleBinding").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} RoleBinding nodes, skipping import.")
    else:
        if "all" in collector or "rolebinding" in collector:
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

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("ClusterRoleBinding").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} ClusterRoleBinding nodes, skipping import.")
    else:
        if "all" in collector or "clusterrolebinding" in collector:
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

    matcher = NodeMatcher(graph)
    existing_count = graph.nodes.match("Route").count()
    if existing_count > 0:
        print(f"⚠️ Database already has {existing_count} Route nodes, skipping import.")
    else:
        if "all" in collector or "route" in collector:
            with Bar('Route',max = len(route_list.items)) as bar:
                for enum in route_list.items:
                    bar.next()
                    # print(enum.metadata)
                    name = enum.metadata.name
                    namespace = enum.metadata.namespace
                    uid = enum.metadata.uid

                    host = enum.spec.host
                    path = enum.spec.path
                    port= "any"
                    if enum.spec.port:
                        port = enum.spec.port.targetPort    

                    try:
                        target_project = next(
                            (p for p in project_list.items if p.metadata.name == namespace),
                            None
                        )
                        projectNode = Node("Project",name=target_project.metadata.name, uid=target_project.metadata.uid)
                        projectNode.__primarylabel__ = "Project"
                        projectNode.__primarykey__ = "uid"

                    except: 
                        projectNode = Node("AbsentProject",name=namespace, uid=namespace)
                        projectNode.__primarylabel__ = "AbsentProject"
                        projectNode.__primarykey__ = "uid"

                    routeNode = Node("Route",name=name, namespace=namespace, uid=uid, host=host, port=port, path=path)
                    routeNode.__primarylabel__ = "Route"
                    routeNode.__primarykey__ = "uid"

                    try:
                        tx = graph.begin()
                        relationShip = Relationship(projectNode, "CONTAIN ROUTE", routeNode)
                        node = tx.merge(projectNode) 
                        node = tx.merge(routeNode) 
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
    ## Pod
    ## 
    print("#### Pod ####")

    if "all" in collector or "pod" in collector:
        matcher = NodeMatcher(graph)
        existing_count = graph.nodes.match("Pod").count()
        if existing_count > 0:
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
        matcher = NodeMatcher(graph)
        existing_count = graph.nodes.match("ConfigMap").count()
        if existing_count > 0:
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
    print("#### Kyverno whitelist ####")

    if "all" in collector or "kyverno" in collector:
        matcher = NodeMatcher(graph)
        existing_count = graph.nodes.match("KyvernoWhitelist").count()
        if existing_count > 0:
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
    ## Gatekeeper 
    ## 
    print("#### Gatekeeper whitelist ####")

    if "all" in collector or "gatekeeper" in collector:
        matcher = NodeMatcher(graph)
        existing_count = graph.nodes.match("GatekeeperWhitelist").count()
        if existing_count > 0:
            print(f"⚠️ Database already has {existing_count} GatekeeperWhitelist nodes, skipping import.")
        else:
            with Bar('Gatekeeper',max = len(validatingWebhookConfiguration_list.items)) as bar:
                for enum in validatingWebhookConfiguration_list.items:
                    bar.next()
                
                    name = enum.metadata.name

                    if "gatekeeper-validating-webhook-configuration" in name:
                        webhooks = enum.webhooks
                        if webhooks:
                            for webhook in enum.webhooks:      

                                webhookName = webhook.name
                                matchExpressions = str(webhook.namespaceSelector.matchExpressions)
                                # print(matchExpressions)
                                try:
                                    gatekeeperWhitelistNode = Node("GatekeeperWhitelist", name=webhookName, uid=webhookName, whitelist=matchExpressions)
                                    gatekeeperWhitelistNode.__primarylabel__ = "GatekeeperWhitelist"
                                    gatekeeperWhitelistNode.__primarykey__ = "uid"


                                    tx = graph.begin()  
                                    node = tx.merge(gatekeeperWhitelistNode) 
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
            

if __name__ == '__main__':
    main()