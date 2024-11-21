import unittest
from unittest.mock import patch, MagicMock
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from OpenShiftGrapher.OpenShiftGrapher import main

from kubernetes.client import  *
from openshift.dynamic import ResourceInstance

from py2neo import Graph, Node


class OpenShiftGrapherTests(unittest.TestCase):

    @patch('sys.argv', ['OpenShiftGrapher','-a','https://cluster.api.net:6443', '-t', 'token', '-c', 'all'])
    @patch("OpenShiftGrapher.OpenShiftGrapher.DynamicClient")
    @patch("OpenShiftGrapher.OpenShiftGrapher.Graph")

    def test1(self, mock_graph, mock_dynamic_client):

        # Create V1Namespace objects with metadata
        project1 = V1Namespace(
            metadata=V1ObjectMeta(name="project1", uid="12345", namespace="namespace1")
        )
        project2 = V1Namespace(
            metadata=V1ObjectMeta(name="project2", uid="67890", namespace="namespace2")
        )
        mock_projects = MagicMock(
            get=MagicMock(side_effect=lambda name=None: (
                project1 if name == "namespace1" else
                project2 if name == "namespace2" else
                MagicMock(items=[project1, project2])  # Return list when name is not provided
            ))
        )

        # Create V1ServiceAccount objects with metadata
        serviceaccount1 = V1ServiceAccount(
            metadata=V1ObjectMeta(name="serviceaccount1", uid="23456", namespace="namespace1")
        )
        serviceaccount2 = V1ServiceAccount(
            metadata=V1ObjectMeta(name="serviceaccount2", uid="34567", namespace="namespace2")
        )
        mock_service_accounts = MagicMock(
            get=MagicMock(side_effect=lambda name=None, namespace=None: (
                serviceaccount1 if name == "serviceaccount1" and namespace == "namespace1" else
                serviceaccount2 if name == "namespace2" and namespace == "namespace2" else
                MagicMock(items=[serviceaccount1, serviceaccount2])  # Return list when name is not provided
            ))
        )

        # Mocking SCC
        scc_metadata = MagicMock(spec=V1ObjectMeta)
        scc_metadata.name = "scc1"
        scc_metadata.uid = "12345"
        scc_metadata.namespace = "default"

        mock_scc_1 = MagicMock(spec=ResourceInstance)
        mock_scc_1.metadata = scc_metadata
        mock_scc_1.allowPrivilegedContainer = True
        mock_scc_1.volumes = ["configMap", "secret"]
        mock_scc_1.runAsUser = {"type": "RunAsAny"}
        mock_scc_1.users = ["system:serviceaccount:namespace1:serviceaccount1", "titi"]

        mock_sccs = MagicMock()
        mock_sccs.get.return_value = MagicMock(items=[mock_scc_1])

        # Create V1Role objects with metadata
        role1 = V1Role(
            metadata=V1ObjectMeta(name="role1", uid="11111", namespace="namespace1")
        )
        role2 = V1Role(
            metadata=V1ObjectMeta(name="role2", uid="22222", namespace="namespace2")
        )

        # Mock roles.get() to return a list or a single role based on the 'name' argument
        mock_roles = MagicMock(
            get=MagicMock(side_effect=lambda name=None: (
                role1 if name == "role1" else
                role2 if name == "role2" else
                MagicMock(items=[role1, role2])  # Return list when name is not provided
            ))
        )

        # Create V1ClusterRole objects with metadata
        clusterrole1 = V1ClusterRole(
            metadata=V1ObjectMeta(name="clusterrole1", uid="33333")
        )
        clusterrole2 = V1ClusterRole(
            metadata=V1ObjectMeta(name="clusterrole2", uid="44444")
        )

        # Mock clusterroles.get() to return a list or a single clusterrole based on the 'name' argument
        mock_clusterroles = MagicMock(
            get=MagicMock(side_effect=lambda name=None: (
                clusterrole1 if name == "clusterrole1" else
                clusterrole2 if name == "clusterrole2" else
                MagicMock(items=[clusterrole1, clusterrole2])  # Return list when name is not provided
            ))
        )

        mock_users = MagicMock(
            get=MagicMock(
                return_value=MagicMock(
                    items=[
                        
                    ]
                )
            )
        )

        mock_groups=MagicMock(
            return_value=MagicMock(
                items=[

                ]
            )
        )

        mock_role_bindings=MagicMock(
            return_value=MagicMock(
                items=[

                ]
            )
        )

        mock_cluster_role_bindings=MagicMock(
            return_value=MagicMock(
                items=[

                ]
            )
        )

        mock_routes=MagicMock(
            return_value=MagicMock(
                items=[

                ]
            )
        )

        mock_pods = MagicMock(
            get=MagicMock(
                return_value=MagicMock(
                    items=[

                    ]
                )
            )
        )

        mock_configmaps = MagicMock(
            get=MagicMock(
                return_value=MagicMock(
                    items=[

                    ]
                )
            )
        )

        mock_validating_webhook = MagicMock(
            get=MagicMock(
                return_value=MagicMock(
                    items=[
                        MagicMock(metadata=MagicMock(name="validatingwebhook1", uid="23456")),
                        MagicMock(metadata=MagicMock(name="validatingwebhook2", uid="34567")),
                    ]
                )
            )
        )
        mock_validating_webhook.get().items[0].metadata.name = "validatingwebhook1"
        mock_validating_webhook.get().items[0].metadata.uid = "23456"
        mock_validating_webhook.get().items[1].metadata.name = "validatingwebhook2"
        mock_validating_webhook.get().items[1].metadata.uid = "34567"


        # Configure `resources.get()` to return the appropriate mock based on arguments
        def mock_get(api_version, kind):
            if api_version == "project.openshift.io/v1" and kind == "Project":
                return mock_projects
            elif api_version == "v1" and kind == "ServiceAccount":
                return mock_service_accounts
            elif api_version == "security.openshift.io/v1" and kind == "SecurityContextConstraints":
                return mock_sccs
            elif api_version == "rbac.authorization.k8s.io/v1" and kind == "Role":
                return mock_roles
            elif api_version == "rbac.authorization.k8s.io/v1" and kind == "ClusterRole":
                return mock_clusterroles
            elif api_version == "v1" and kind == "User":
                return mock_users
            elif api_version == "v1" and kind == "Group":
                return mock_groups
            elif api_version == "rbac.authorization.k8s.io/v1" and kind == "RoleBinding":
                return mock_role_bindings
            elif api_version == "rbac.authorization.k8s.io/v1" and kind == "ClusterRoleBinding":
                return mock_cluster_role_bindings
            elif api_version == "route.openshift.io/v1" and kind == "Route":
                return mock_routes
            elif api_version == "v1" and kind == "Pod":
                return mock_pods
            elif api_version == "v1" and kind == "ConfigMap":
                return mock_configmaps
            elif api_version == "v1" and kind == "ValidatingWebhookConfiguration":
                return mock_validating_webhook
            else:
                raise ValueError(f"Unexpected api_version={api_version}, kind={kind}")

        mock_dynamic_client.return_value.resources.get.side_effect = mock_get

        main()
        

if __name__ == "__main__":
    unittest.main()