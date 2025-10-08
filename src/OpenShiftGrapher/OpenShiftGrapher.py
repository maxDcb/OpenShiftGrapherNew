import argparse
from argparse import RawTextHelpFormatter
import sys
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from py2neo import Graph

from OpenShiftGrapher.collectors import (
    import_clusterrolebindings,
    import_clusterroles,
    import_configmaps,
    import_gatekeeper_whitelists,
    import_groups,
    import_kyverno_whitelists,
    import_pods,
    import_projects,
    import_rolebindings,
    import_roles,
    import_routes,
    import_scc,
    import_service_accounts,
    import_users,
)

from kubernetes import client
from openshift.dynamic import DynamicClient
from openshift.helper.userpassauth import OCPLoginConfiguration
 

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


    project_items = import_projects(graph, collector, project_list, release)
    service_account_items = import_service_accounts(
        graph,
        collector,
        project_items,
        serviceAccount_list,
        release,
    )
    scc_items = import_scc(graph, collector, SCC_list, release)
    role_items = import_roles(graph, collector, role_list, scc_items, release)
    clusterrole_items = import_clusterroles(
        graph,
        collector,
        clusterrole_list,
        scc_items,
        release,
    )
    user_items = import_users(graph, collector, user_list, release)
    group_items = import_groups(graph, collector, group_list, user_items, release)

    import_rolebindings(
        graph,
        collector,
        roleBinding_list,
        role_items,
        clusterrole_items,
        project_items,
        group_items,
        user_items,
        service_account_items,
        release,
    )

    import_clusterrolebindings(
        graph,
        collector,
        clusterRoleBinding_list,
        role_items,
        clusterrole_items,
        project_items,
        group_items,
        user_items,
        service_account_items,
        release,
    )

    import_routes(graph, collector, route_list, project_items, release)
    import_pods(graph, collector, pod_list, project_items, release)
    import_configmaps(
        graph,
        collector,
        configmap_list,
        project_items,
        release,
    )

    import_kyverno_whitelists(
        graph,
        collector,
        kyverno_logs,
        project_items,
        service_account_items,
        release,
    )

    import_gatekeeper_whitelists(
        graph,
        collector,
        validatingWebhookConfiguration_list,
        release,
    )


if __name__ == '__main__':
    main()
