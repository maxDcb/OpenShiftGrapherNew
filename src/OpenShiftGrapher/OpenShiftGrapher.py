"""CLI entry point for the OpenShift Grapher collectors."""

import argparse
import json
from argparse import RawTextHelpFormatter
from pathlib import Path
from typing import Any, Sequence

import urllib3
from kubernetes import client
from openshift.dynamic import DynamicClient
from openshift.helper.userpassauth import OCPLoginConfiguration
from py2neo import Graph

from .collectors import run_collectors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GRAPH_URI = "bolt://localhost:7687"
DEFAULT_DATABASE_NAME = "neo4j"
DEFAULT_NEO4J_USER = "neo4j"
DEFAULT_NEO4J_PASSWORD = "rootroot"
RESET_CONFIRM_PROMPT = "are you sure your want to reset the db? (y/n)"

INIT_OC_HEADER = "#### Init OC ####"
INIT_NEO4J_HEADER = "#### Init neo4j ####"
FETCH_RESOURCES_HEADER = "#### Fetch resources ####"
KYVERNO_FETCH_MESSAGE = "Fetching Kyverno logs from pods"
TOKEN_EXPIRED_MESSAGE = "\n⚠️  Your OpenShift API token has expired."
TOKEN_PROMPT = "Please enter a new Bearer token: "

FETCH_MESSAGES = {
    "oauth": "Fetching OAuth",
    "identity": "Fetching Identity",
    "project": "Fetching Projects",
    "service_account": "Fetching ServiceAccounts",
    "security_context_constraints": "Fetching SecurityContextConstraints",
    "role": "Fetching Roles",
    "cluster_role": "Fetching ClusterRoles",
    "user": "Fetching Users",
    "group": "Fetching Groups",
    "role_binding": "Fetching RoleBindings",
    "cluster_role_binding": "Fetching ClusterRoleBindings",
    "route": "Fetching Routes",
    "pod": "Fetching Pods",
    "configmap": "Fetching ConfigMaps",
    "validating_webhook_configuration": "Fetching ValidatingWebhookConfigurations",
    "mutating_webhook_configuration": "Fetching MutatingWebhookConfiguration",
    "cluster_policy": "Fetching ClusterPolicy",
}


def refresh_token() -> str:
    """Ask the user for a new token interactively."""
    print(TOKEN_EXPIRED_MESSAGE)
    new_token = input(TOKEN_PROMPT).strip()
    if not new_token:
        raise ValueError("Token cannot be empty.")
    return new_token


def build_clients(api_key: str, host_api: str, proxy_url: str | None = None):
    """Create Kubernetes and OpenShift dynamic clients."""
    kube_config = OCPLoginConfiguration(host=host_api)
    kube_config.verify_ssl = False
    kube_config.token = api_key
    kube_config.api_key = {"authorization": f"Bearer {api_key}"}

    k8s_client = client.ApiClient(kube_config)

    if proxy_url:
        proxy_manager = urllib3.ProxyManager(proxy_url)
        k8s_client.rest_client.pool_manager = proxy_manager

    dyn_client = DynamicClient(k8s_client)
    v1 = client.CoreV1Api(k8s_client)
    return dyn_client, v1


def fetch_resource_with_refresh(
    dyn_client: DynamicClient,
    api_key: str,
    hostApi: str,
    proxyUrl: str | None,
    api_version: str,
    kind: str,
):
    """Fetch a resource list from OpenShift with automatic token refresh on 401."""
    try:
        resource = dyn_client.resources.get(api_version=api_version, kind=kind)
        resource_list = resource.get()
        return resource_list, dyn_client, api_key
    except client.exceptions.ApiException as exc:
        if exc.status == 401:
            api_key = refresh_token()
            dyn_client, _ = build_clients(api_key, hostApi, proxyUrl)
            resource = dyn_client.resources.get(api_version=api_version, kind=kind)
            resource_list = resource.get()
            return resource_list, dyn_client, api_key
        print(f"[-] Error fetching {kind}: {exc}")
        raise


def normalise_collectors(collector: str | Sequence[str]) -> list[str]:
    """Return a lowercase list of collector names."""
    if isinstance(collector, str):
        return [collector.lower()]
    return [item.lower() for item in collector]


def _json_default(obj: Any) -> Any:
    """Fallback serializer for objects that are not JSON serializable by default."""
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return obj.to_dict()
    if isinstance(obj, set):
        return sorted(obj)
    return str(obj)


def backup_resource_data(
    output_directory: Path,
    resources: dict[str, Any],
    kyverno_logs: dict[str, str],
) -> None:
    """Persist fetched resource data to JSON files inside *output_directory*."""

    output_directory.mkdir(parents=True, exist_ok=True)
    for resource_name, resource_content in resources.items():
        resource_path = output_directory / f"{resource_name}.json"
        serialisable_content = (
            resource_content.to_dict()
            if hasattr(resource_content, "to_dict") and callable(resource_content.to_dict)
            else resource_content
        )
        with resource_path.open("w", encoding="utf-8") as resource_file:
            json.dump(serialisable_content, resource_file, indent=2, default=_json_default)

    if kyverno_logs:
        kyverno_path = output_directory / "kyverno_logs.json"
        with kyverno_path.open("w", encoding="utf-8") as kyverno_file:
            json.dump(kyverno_logs, kyverno_file, indent=2, default=_json_default)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Exemple:\n"
            "        OpenShiftGrapher -a \"https://api.cluster.net:6443\" -t \"eyJhbGciOi...\"\n"
            "        OpenShiftGrapher -a \"https://api.cluster.net:6443\" -t $(cat token.txt) -c all -d customDB -u neo4j -p rootroot -r\n"
            "        OpenShiftGrapher -a \"https://api.cluster.net:6443\" -t $(cat token.txt) -c securitycontextconstraints role route"
        ),
        formatter_class=RawTextHelpFormatter,
    )

    parser.add_argument('-r', '--resetDB', action="store_true", help='reset the neo4j db.')
    parser.add_argument('-a', '--apiUrl', required=True, help='api url.')
    parser.add_argument('-t', '--token', required=True, help='service account token.')
    parser.add_argument(
        '-c',
        '--collector',
        nargs="+",
        default="all",
        help='list of collectors. Possible values: all, project, scc, securitycontextconstraints, sa, role, '
             'clusterrole, rolebinding, clusterrolebinding, route, pod, kyverno, '
             'validatingwebhookconfiguration, mutatingwebhookconfiguration, clusterpolicies'
    )
    parser.add_argument('-u', '--userNeo4j', default=DEFAULT_NEO4J_USER, help='neo4j database user.')
    parser.add_argument('-p', '--passwordNeo4j', default=DEFAULT_NEO4J_PASSWORD, help='neo4j database password.')
    parser.add_argument('-x', '--proxyUrl', default="", help='proxy url.')
    parser.add_argument('-d', '--databaseName', default=DEFAULT_DATABASE_NAME, help='Database Name.')
    parser.add_argument(
        '--backupResources',
        action='store_true',
        help='Backup fetched resources into files named after the database.',
    )

    args = parser.parse_args()

    host_api = args.apiUrl
    api_key = args.token
    reset_db = args.resetDB
    user_neo4j = args.userNeo4j
    password_neo4j = args.passwordNeo4j
    collector = args.collector
    proxy_url = args.proxyUrl
    database_name = args.databaseName
    backup_resources_enabled = args.backupResources

    release = True

    print(INIT_OC_HEADER)
    dyn_client, _ = build_clients(api_key, host_api, proxy_url)

    print(INIT_NEO4J_HEADER)
    graph = Graph(GRAPH_URI, name=database_name, user=user_neo4j, password=password_neo4j)
    if reset_db:
        if input(RESET_CONFIRM_PROMPT) != "y":
            raise SystemExit()
        graph.delete_all()

    print(FETCH_RESOURCES_HEADER)

    print(FETCH_MESSAGES["oauth"])
    oauth_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, "config.openshift.io/v1", "OAuth"
    )

    print(FETCH_MESSAGES["identity"])
    identity_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, "user.openshift.io/v1", "Identity"
    )

    print(FETCH_MESSAGES["project"])
    project_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, "project.openshift.io/v1", "Project"
    )

    print(FETCH_MESSAGES["service_account"])
    service_account_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, 'v1', 'ServiceAccount'
    )

    print(FETCH_MESSAGES["security_context_constraints"])
    security_context_constraints_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, 'security.openshift.io/v1', 'SecurityContextConstraints'
    )

    print(FETCH_MESSAGES["role"])
    role_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, 'rbac.authorization.k8s.io/v1', 'Role'
    )

    print(FETCH_MESSAGES["cluster_role"])
    clusterrole_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, 'rbac.authorization.k8s.io/v1', 'ClusterRole'
    )

    print(FETCH_MESSAGES["user"])
    user_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, 'user.openshift.io/v1', 'User'
    )

    print(FETCH_MESSAGES["group"])
    group_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, 'user.openshift.io/v1', 'Group'
    )

    print(FETCH_MESSAGES["role_binding"])
    role_binding_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, 'rbac.authorization.k8s.io/v1', 'RoleBinding'
    )

    print(FETCH_MESSAGES["cluster_role_binding"])
    cluster_role_binding_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, 'rbac.authorization.k8s.io/v1', 'ClusterRoleBinding'
    )

    print(FETCH_MESSAGES["route"])
    route_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, 'route.openshift.io/v1', 'Route'
    )

    print(FETCH_MESSAGES["pod"])
    pod_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, 'v1', 'Pod'
    )

    print(KYVERNO_FETCH_MESSAGE)
    kyverno_logs: dict[str, str] = {}
    for pod in pod_list.items:
        name = pod.metadata.name
        namespace = pod.metadata.namespace
        uid = pod.metadata.uid

        if "kyverno-admission-controller" in name:
            try:
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
                kyverno_logs[uid] = log_text
            except Exception as exc:  # pragma: no cover - best effort logging
                print(f"[-] Failed to get logs for {name}: {exc}")
                continue

    print(FETCH_MESSAGES["configmap"])
    configmap_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, 'v1', 'ConfigMap'
    )

    print(FETCH_MESSAGES["validating_webhook_configuration"])
    validating_webhook_configuration_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, 'admissionregistration.k8s.io/v1', 'ValidatingWebhookConfiguration'
    )

    print(FETCH_MESSAGES["mutating_webhook_configuration"])
    mutating_webhook_configuration_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, 'admissionregistration.k8s.io/v1', 'MutatingWebhookConfiguration'
    )

    print(FETCH_MESSAGES["cluster_policy"])
    cluster_policy_list, dyn_client, api_key = fetch_resource_with_refresh(
        dyn_client, api_key, host_api, proxy_url, 'kyverno.io/v1', 'ClusterPolicy'
    )

    if backup_resources_enabled:
        backup_directory = Path(f"{database_name}_ressources")
        resources_to_backup = {
            "oauth": oauth_list,
            "identity": identity_list,
            "project": project_list,
            "service_account": service_account_list,
            "security_context_constraints": security_context_constraints_list,
            "role": role_list,
            "cluster_role": clusterrole_list,
            "user": user_list,
            "group": group_list,
            "role_binding": role_binding_list,
            "cluster_role_binding": cluster_role_binding_list,
            "route": route_list,
            "pod": pod_list,
            "configmap": configmap_list,
            "validating_webhook_configuration": validating_webhook_configuration_list,
            "mutating_webhook_configuration": mutating_webhook_configuration_list,
            "cluster_policy": cluster_policy_list,
        }
        backup_resource_data(backup_directory, resources_to_backup, kyverno_logs)

    run_collectors(
        graph=graph,
        collector=normalise_collectors(collector),
        release=release,
        oauth_list=oauth_list,
        identity_list=identity_list,
        project_list=project_list,
        serviceAccount_list=service_account_list,
        security_context_constraints_list=security_context_constraints_list,
        role_list=role_list,
        clusterrole_list=clusterrole_list,
        user_list=user_list,
        group_list=group_list,
        roleBinding_list=role_binding_list,
        clusterRoleBinding_list=cluster_role_binding_list,
        route_list=route_list,
        pod_list=pod_list,
        kyverno_logs=kyverno_logs,
        configmap_list=configmap_list,
        validatingWebhookConfiguration_list=validating_webhook_configuration_list,
        mutatingWebhookConfiguration_list=mutating_webhook_configuration_list,
        clusterPolicy_list=cluster_policy_list,
    )


if __name__ == "__main__":
    main()
