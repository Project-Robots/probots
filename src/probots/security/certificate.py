""" A module for working with certificates. """

from socket import getfqdn, gethostname

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from probots import security


class NodeCertificate:
    """Certificate class."""

    key: rsa.RSAPrivateKey = None
    cert: x509.Certificate = None
    csr: x509.CertificateSigningRequest = None

    key_file: str = None
    cert_file: str = None
    csr_file: str = None

    def __init__(self, key_file: str, cert_file: str, csr_file: str):
        """Constructor."""
        self.key_file = key_file
        self.cert_file = cert_file
        self.csr_file = csr_file

        self.key = security.load_private_key(private_key_file=key_file)
        self.cert = security.load_certificate(certificate_file=cert_file)
        self.csr = security.load_csr(csr_file=csr_file)

        if self.key is None:
            self.key = rsa.generate_private_key(
                public_exponent=security.PUBLIC_EXPONENT,
                key_size=security.KEY_SIZE,
                backend=default_backend(),
            )

        if self.csr is None:
            subject = x509.Name(
                attributes=[
                    x509.NameAttribute(
                        oid=NameOID.COMMON_NAME,
                        value=getfqdn(),
                    ),
                    x509.NameAttribute(
                        oid=NameOID.ORGANIZATION_NAME,
                        value="Xovrenia Inc.",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.ORGANIZATIONAL_UNIT_NAME,
                        value="IT andSecurity Engineering",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.COUNTRY_NAME,
                        value="US",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.STATE_OR_PROVINCE_NAME,
                        value="California",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.LOCALITY_NAME,
                        value="Placentia",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.POSTAL_CODE,
                        value="92870",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.EMAIL_ADDRESS,
                        value="xovrenia@thoughtparameters.com",
                    ),
                ]
            )

            self.csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(name=subject)
                .add_extension(
                    x509.SubjectAlternativeName(
                        general_names=[
                            x509.DNSName(gethostname()),
                            x509.DNSName(f"{gethostname()}.xovrenia.inc"),
                            x509.DNSName(f"eva.{gethostname()}.xovrenia.inc"),
                            x509.DNSName(f"drift.{gethostname()}.xovrenia.inc"),
                            x509.DNSName(f"astro.{gethostname()}.xovrenia.inc"),
                            x509.DNSName(f"sentra.{gethostname()}.xovrenia.inc"),
                            x509.DNSName(f"orbit.{gethostname()}.xovrenia.inc"),
                        ]
                    ),
                    critical=False,
                )
                .sign(
                    private_key=self.key,
                    rsa_padding=security.RSA_PADDING,
                    algorithm=hashes.SHA256(),
                    backend=default_backend(),
                )
            )

            if self.cert is None:
                print("Certificate not found. Must sign CSR with Intermediate CA.")

    def save(self, save_key=False, save_csr=False, save_cert=False):
        """Save the certificate to file."""
        saved_key = False
        saved_cert = False
        saved_csr = False

        try:
            if save_key:
                with open(self.key_file, "wb") as f:
                    f.write(buffer=security.private_key_to_pem(private_key=self.key))
                saved_key = True
        except OSError as e:
            print(f"Error saving private key: {e}")

        try:
            if save_csr:
                with open(self.csr_file, "wb") as f:
                    f.write(self.csr.public_bytes(serialization.Encoding.PEM))
                saved_csr = True
        except OSError as e:
            print(f"Error saving CSR: {e}")

        try:
            if save_cert:
                with open(self.cert_file, "wb") as f:
                    f.write(self.cert.public_bytes(serialization.Encoding.PEM))
                saved_cert = True
        except OSError as e:
            print(f"Error saving certificate: {e}")

        return (saved_key, saved_csr, saved_cert)

    def get_certificate(self) -> x509.Certificate:
        """Get the certificate."""
        return self.cert

    def set_certificate(self, certificate: x509.Certificate):
        """Set the certificate."""
        self.cert = certificate

    def get_csr(self) -> x509.CertificateSigningRequest:
        """Get the certificate signing request."""
        return self.csr
