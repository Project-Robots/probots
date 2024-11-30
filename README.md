# probots

[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

Project Robots Python module

## Installation

```bash
pip install probots
```

## Usage

```python
from probots.security.ca import RootCertificateAuthority, IntermediateCertificateAuthority
from probots.security.certificate import NodeCertificate

root_ca = RootCertificateAuthority(key_file="/etc/robots/ca/root_ca.key", cert_file="/etc/robots/ca/root_ca.crt")
root_ca.save()

intermediate_ca = IntermediateCertificateAuthority(rootca_key=root_ca.key, rootca_cert=root_ca.cert, key_file="/etc/robots/ca/intermediate_ca.key", cert_file="/etc/robots/ca/intermediate_ca.crt")
intermediate_ca.save()

node_cert = NodeCertificate(private_key_file="/etc/robots/tls/node.key", certificate_file="/etc/robots/tls/node.crt", csr_file="/etc/robots/tls/node.csr")

node_cert.set_certificate(intermediate_ca.sign(node_cert.get_csr()))

node_cert.save(save_key=True, save_cert=True, save_csr=True)

