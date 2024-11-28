from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="OpenShiftGrapher",
    version="0.3",
    packages=find_packages(where='src'),
    long_description=long_description,
    long_description_content_type="text/markdown",
    package_dir={'': 'src'},
    install_requires=[
        "py2neo",
        "openshift",
        "progress",
    ],
    entry_points={
        'console_scripts': [
            'OpenShiftGrapher=OpenShiftGrapher.OpenShiftGrapher:main', 
        ],
    },
    author="Maxime de Caumia Baillenx",
    description="Create relational databases, in neo4j, of an OpenShift cluster.",
)
