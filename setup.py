from setuptools import setup, find_packages

setup(
    name="probots",
    version="0.0.1",
    packages=find_packages(include=["probots", "probots.security.*", "probots.pki.*"]),
)
