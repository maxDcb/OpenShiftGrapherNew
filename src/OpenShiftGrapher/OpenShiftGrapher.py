import argparse
from argparse import RawTextHelpFormatter
import sys
import os
import re

import json
import subprocess

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from py2neo import Graph, Node, Relationship

import yaml
from kubernetes import client
from openshift.dynamic import DynamicClient
from openshift.helper.userpassauth import OCPLoginConfiguration

from progress.bar import Bar
 

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
    parser.add_argument('-c', '--collector', nargs="+", default=[], help='list of collectors. Possible values: all, project, scc, sa, role, clusterrole, rolebinding, clusterrolebinding, route, pod ')
    parser.add_argument('-u', '--userNeo4j', default="neo4j", help='neo4j database user.')
    parser.add_argument('-p', '--passwordNeo4j', default="rootroot", help='neo4j database password.')
    parser.add_argument('-x', '--proxyUrl', default="", help='proxy url.')

    args = parser.parse_args()

    hostApi = args.apiUrl
    api_key = args.token
    resetDB = args.resetDB
    userNeo4j = args.userNeo4j
    passwordNeo4j = args.passwordNeo4j
    collector = args.collector
    proxyUrl = args.proxyUrl

    release = True


    ##
    ## Init OC
    ##
    print("#### Init OC ####")

    kubeConfig = OCPLoginConfiguration(host=hostApi)
    kubeConfig.verify_ssl = False
    kubeConfig.token = api_key
    kubeConfig.api_key = {"authorization": "Bearer {}".format(api_key)}

    k8s_client = client.ApiClient(kubeConfig)

    if proxyUrl:
        proxyManager = urllib3.ProxyManager(proxyUrl)
        k8s_client.rest_client.pool_manager = proxyManager
        # k8s_client.configuration.debug = True

    dyn_client = DynamicClient(k8s_client)
    v1 = client.CoreV1Api(k8s_client)


    ##
    ## Init neo4j
    ##
    print("#### Init neo4j ####")

    graph = Graph("bolt://localhost:7687", user=userNeo4j, password=passwordNeo4j)
    if resetDB:
        if input("are you sure your want to reset the db? (y/n)") != "y":
            exit()
        graph.delete_all()


    ##
    ## Project
    ##
    print("#### Project ####")

    projects = dyn_client.resources.get(api_version='project.openshift.io/v1', kind='Project')
    project_list = projects.get()

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

    serviceAccounts = dyn_client.resources.get(api_version='v1', kind='ServiceAccount')
    serviceAccount_list = serviceAccounts.get()
     
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
                        project_list = projects.get(name=enum.metadata.namespace)
                        projectNode = Node("Project",name=project_list.metadata.name, uid=project_list.metadata.uid)
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

    SCCs = dyn_client.resources.get(api_version='security.openshift.io/v1', kind='SecurityContextConstraints')
    SCC_list = SCCs.get()
     
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
                                        project_list = projects.get(name=subjectNamespace)
                                        projectNode = Node("Project",name=project_list.metadata.name, uid=project_list.metadata.uid)
                                        projectNode.__primarylabel__ = "Project"
                                        projectNode.__primarykey__ = "uid"

                                    except: 
                                        projectNode = Node("AbsentProject", name=subjectNamespace, uid=subjectNamespace)
                                        projectNode.__primarylabel__ = "AbsentProject"
                                        projectNode.__primarykey__ = "uid"

                                    try:
                                        serviceAccount = serviceAccounts.get(name=subjectName, namespace=subjectNamespace)
                                        subjectNode = Node("ServiceAccount",name=serviceAccount.metadata.name, namespace=serviceAccount.metadata.namespace, uid=serviceAccount.metadata.uid)
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

    roles = dyn_client.resources.get(api_version='rbac.authorization.k8s.io/v1', kind='Role')
    role_list = roles.get()
     
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
                                                    SCC_list = SCCs.get(name=resourceName)
                                                    sccNode = Node("SCC", name=SCC_list.metadata.name, uid=SCC_list.metadata.uid)
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
                                                resourceName = apiGroup
                                                resourceName = ":"
                                                resourceName = resource

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

    clusterroles = dyn_client.resources.get(api_version='rbac.authorization.k8s.io/v1', kind='ClusterRole')
    clusterrole_list = clusterroles.get()
     
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
                                                    SCC_list = SCCs.get(name=resourceName)
                                                    sccNode = Node("SCC", name=SCC_list.metadata.name, uid=SCC_list.metadata.uid)
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
                                                resourceName = apiGroup
                                                resourceName = ":"
                                                resourceName = resource

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

    users = dyn_client.resources.get(api_version='v1', kind='User')
    user_list = users.get()

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

    groups = dyn_client.resources.get(api_version='v1', kind='Group')
    group_list = groups.get()

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
                            user_list = users.get(name=user)
                            # print(user_list)
                            userNode = Node("User", name=user_list.metadata.name, uid=user_list.metadata.uid)
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

    roleBindings = dyn_client.resources.get(api_version='rbac.authorization.k8s.io/v1', kind='RoleBinding')
    roleBinding_list = roleBindings.get()

    if "all" in collector or "rolebinding" in collector:
        with Bar('RoleBinding',max = len(roleBinding_list.items)) as bar:

            for enum in roleBinding_list.items:
                bar.next()

                print(enum)
                name = enum.metadata.name
                uid = enum.metadata.uid
                namespace = enum.metadata.namespace
                description = enum.metadata.description

                rolebindingNode = Node("RoleBinding", name=name, namespace=namespace, uid=enum.metadata.uid)
                rolebindingNode.__primarylabel__ = "RoleBinding"
                rolebindingNode.__primarykey__ = "uid"

                roleKind = enum.roleRef.kind
                roleName = enum.roleRef.name

                if roleKind == "ClusterRole":
                    try:
                        role = clusterroles.get(name=roleName)
                        roleNode = Node("ClusterRole",name=role.metadata.name, uid=role.metadata.uid)
                        roleNode.__primarylabel__ = "ClusterRole"
                        roleNode.__primarykey__ = "uid"

                    except: 
                        roleNode = Node("AbsentClusterRole", name=roleName, uid=roleName)
                        roleNode.__primarylabel__ = "AbsentClusterRole"
                        roleNode.__primarykey__ = "uid"

                elif roleKind == "Role":
                    try:
                        role = roles.get(name=roleName, namespace=enum.metadata.namespace)
                        roleNode = Node("Role",name=role.metadata.name, namespace=role.metadata.namespace, uid=role.metadata.uid)
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
                                    project_list = projects.get(name=subjectNamespace)
                                    projectNode = Node("Project",name=project_list.metadata.name, uid=project_list.metadata.uid)
                                    projectNode.__primarylabel__ = "Project"
                                    projectNode.__primarykey__ = "uid"

                                except: 
                                    projectNode = Node("AbsentProject", name=subjectNamespace, uid=subjectNamespace)
                                    projectNode.__primarylabel__ = "AbsentProject"
                                    projectNode.__primarykey__ = "uid"

                                try:
                                    serviceAccount = serviceAccounts.get(name=subjectName, namespace=subjectNamespace)
                                    subjectNode = Node("ServiceAccount",name=serviceAccount.metadata.name, namespace=serviceAccount.metadata.namespace, uid=serviceAccount.metadata.uid)
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
                                    project_list = projects.get(name=groupNamespace)
                                    groupNode = Node("Project",name=project_list.metadata.name, uid=project_list.metadata.uid)
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
                                    group_list = groups.get(name=subjectName)
                                    groupNode = Node("Group", name=group_list.metadata.name, uid=group_list.metadata.uid)
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
                                user_list = users.get(name=subjectName)
                                userNode = Node("User", name=user_list.metadata.name, uid=user_list.metadata.uid)
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

    clusterRoleBindings = dyn_client.resources.get(api_version='rbac.authorization.k8s.io/v1', kind='ClusterRoleBinding')
    clusterRoleBinding_list = clusterRoleBindings.get()
     
    if "all" in collector or "clusterrolebinding" in collector:
        with Bar('ClusterRoleBinding',max = len(clusterRoleBinding_list.items)) as bar:
            for enum in clusterRoleBinding_list.items:
                bar.next()

                # print(enum)
                name = enum.metadata.name
                uid = enum.metadata.uid
                namespace = enum.metadata.namespace
                description = enum.metadata.description

                clusterRolebindingNode = Node("ClusterRoleBinding", name=name, namespace=namespace, uid=uid)
                clusterRolebindingNode.__primarylabel__ = "ClusterRoleBinding"
                clusterRolebindingNode.__primarykey__ = "uid"

                roleKind = enum.roleRef.kind
                roleName = enum.roleRef.name

                if roleKind == "ClusterRole":
                    try:
                        role = clusterroles.get(name=roleName)
                        roleNode = Node("ClusterRole",name=role.metadata.name, uid=role.metadata.uid)
                        roleNode.__primarylabel__ = "ClusterRole"
                        roleNode.__primarykey__ = "uid"

                    except: 
                        roleNode = Node("AbsentClusterRole",name=roleName, uid=roleName)
                        roleNode.__primarylabel__ = "AbsentClusterRole"
                        roleNode.__primarykey__ = "uid"

                elif roleKind == "Role":
                    try:
                        role = roles.get(name=roleName, namespace=enum.metadata.namespace)
                        roleNode = Node("Role",name=role.metadata.name, namespace=role.metadata.namespace, uid=role.metadata.uid)
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
                                    project_list = projects.get(name=subjectNamespace)
                                    projectNode = Node("Project",name=project_list.metadata.name, uid=project_list.metadata.uid)
                                    projectNode.__primarylabel__ = "Project"
                                    projectNode.__primarykey__ = "uid"

                                except: 
                                    projectNode = Node("AbsentProject", name=subjectNamespace, uid=subjectNamespace)
                                    projectNode.__primarylabel__ = "AbsentProject"
                                    projectNode.__primarykey__ = "uid"

                                try:
                                    serviceAccount = serviceAccounts.get(name=subjectName, namespace=subjectNamespace)
                                    subjectNode = Node("ServiceAccount",name=serviceAccount.metadata.name, namespace=serviceAccount.metadata.namespace, uid=serviceAccount.metadata.uid)
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
                                    project_list = projects.get(name=groupNamespace)
                                    groupNode = Node("Project",name=project_list.metadata.name, uid=project_list.metadata.uid)
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
                                    group_list = groups.get(name=subjectName)
                                    groupNode = Node("Group", name=group_list.metadata.name, uid=group_list.metadata.uid)
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
                                user_list = users.get(name=subjectName)
                                userNode = Node("User", name=user_list.metadata.name, uid=user_list.metadata.uid)
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

        routes = dyn_client.resources.get(api_version='route.openshift.io/v1', kind='Route')
        route_list = routes.get()

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
                    project_list = projects.get(name=namespace)
                    projectNode = Node("Project",name=project_list.metadata.name, uid=project_list.metadata.uid)
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

    # if "all" in collector or "pod" in collector:
    if "pod" in collector:
        pods = dyn_client.resources.get(api_version='v1', kind='Pod')
        pod_list = pods.get()

        with Bar('Pod',max = len(pod_list.items)) as bar:
            for enum in pod_list.items:
                bar.next()
                # print(enum.metadata)

                name = enum.metadata.name
                namespace = enum.metadata.namespace
                uid = enum.metadata.uid

                try:
                    project_list = projects.get(name=namespace)
                    projectNode = Node("Project",name=project_list.metadata.name, uid=project_list.metadata.uid)
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

    # if "all" in collector or "configmap" in collector:
    if "configmap" in collector:
        configmaps = dyn_client.resources.get(api_version='v1', kind='ConfigMap')
        configmap_list = configmaps.get()

        with Bar('ConfigMap',max = len(configmap_list.items)) as bar:
            for enum in configmap_list.items:
                bar.next()
                # print(enum.metadata)

                name = enum.metadata.name
                namespace = enum.metadata.namespace
                uid = enum.metadata.uid

                try:
                    project_list = projects.get(name=namespace)
                    projectNode = Node("Project",name=project_list.metadata.name, uid=project_list.metadata.uid)
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
        pods = dyn_client.resources.get(api_version='v1', kind='Pod')
        pod_list = pods.get()

        with Bar('Kyverno',max = len(pod_list.items)) as bar:
            for enum in pod_list.items:
                bar.next()
                # print(enum.metadata)

                name = enum.metadata.name
                namespace = enum.metadata.namespace
                uid = enum.metadata.uid

                if "kyverno-admission-controller" in name:
                    api_response = ""
                    try:
                        api_response = v1.read_namespaced_pod_log(name=name, namespace=namespace)

                    except Exception as e:
                        try:
                            containerList = re.search(r'choose one of: [(.+)]', str(e), re.IGNORECASE).group(1)
                            containerList = containerList.split(" ")
                            for container in containerList:
                                api_response = v1.read_namespaced_pod_log(name=name, namespace=namespace, container=container)

                        except Exception as t:
                            print("\n[-] error read_namespaced_pod_log: "+ str(t))  
                            continue

                    # TODO do the same with excludeGroups, excludeRoles, excludedClusterRoles
                    try:
                        excludedUsernameList = re.search(r'excludeUsernames=[(.+)]', api_response, re.IGNORECASE).group(1)
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
                                        project_list = projects.get(name=subjectNamespace)
                                        projectNode = Node("Project",name=project_list.metadata.name, uid=project_list.metadata.uid)
                                        projectNode.__primarylabel__ = "Project"
                                        projectNode.__primarykey__ = "uid"

                                    except: 
                                        projectNode = Node("AbsentProject", name=subjectNamespace, uid=subjectNamespace)
                                        projectNode.__primarylabel__ = "AbsentProject"
                                        projectNode.__primarykey__ = "uid"

                                    try:
                                        serviceAccount = serviceAccounts.get(name=subjectName, namespace=subjectNamespace)
                                        subjectNode = Node("ServiceAccount",name=serviceAccount.metadata.name, namespace=serviceAccount.metadata.namespace, uid=serviceAccount.metadata.uid)
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
        validatingWebhookConfiguration = dyn_client.resources.get(api_version='v1', kind='ValidatingWebhookConfiguration')
        validatingWebhookConfiguration_list = validatingWebhookConfiguration.get()

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
                            print(matchExpressions)
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