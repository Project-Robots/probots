from setuptools import find_packages, setup

setup(
    name="probots",
    version="0.0.3",
    packages=find_packages(include=["probots", "probots.security.*"]),
)
