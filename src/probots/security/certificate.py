""" A module for working with certificates. """

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from socket import gethostname, getfqdn
import probots.security as security


class NodeCertificate:
    """Certificate class."""

    private_key: rsa.RSAPrivateKey = None
    certificate: x509.Certificate = None
    csr: x509.CertificateSigningRequest = None

    private_key_file: str = None
    certificate_file: str = None
    csr_file: str = None

    def __init__(self, private_key_file: str, certificate_file: str, csr_file: str):
        """Constructor."""
        self.private_key_file = private_key_file
        self.certificate_file = certificate_file
        self.csr_file = csr_file

        self.private_key = security.load_private_key(private_key_file)
        self.certificate = security.load_certificate(certificate_file)
        self.csr = security.load_csr(csr_file=csr_file)

        if self.private_key is None:
            self.private_key = rsa.generate_private_key(
                public_exponent=security.PUBLIC_EXPONENT,
                key_size=security.KEY_SIZE,
                backend=default_backend(),
            )

        if self.csr is None:
            self.csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(
                    x509.Name(
                        [
                            x509.NameAttribute(x509.NameOID.COMMON_NAME, getfqdn()),
                            x509.NameAttribute(
                                x509.NameOID.ORGANIZATION_NAME, "Xorvenia"
                            ),
                            x509.NameAttribute(
                                x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
                                "IT and Security Engineering",
                            ),
                            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
                            x509.NameAttribute(
                                x509.NameOID.STATE_OR_PROVINCE_NAME, "California"
                            ),
                            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Placentia"),
                            x509.NameAttribute(x509.NameOID.POSTAL_CODE, "92870"),
                            x509.NameAttribute(
                                x509.NameOID.EMAIL_ADDRESS,
                                "xorvenia@thoughtparameters.com",
                            ),
                        ]
                    )
                )
                .add_extension(
                    x509.SubjectAlternativeName(
                        general_names=[
                            x509.DNSName(gethostname()),
                            x509.DNSName(f"{gethostname()}.xovrenia.security"),
                        ]
                    ),
                    critical=False,
                )
                .sign(
                    private_key=self.private_key,
                    rsa_padding=security.RSA_PADDING,
                    algorithm=hashes.SHA256(),
                    backend=default_backend(),
                )
            )

            if self.certificate is None:
                print(f"Certificate not found. Must sign CSR with Intermediate CA.")

            # self.save(save_key=True, save_csr=True, save_cert=False)

    def save(self, save_key=False, save_csr=False, save_cert=False):
        """Save the certificate to file."""
        saved_private = False
        saved_certificate = False
        saved_csr = False

        try:
            if save_key:
                with open(self.private_key_file, "wb") as f:
                    f.write(
                        self.private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption(),
                        )
                    )
                saved_private = True
        except Exception as e:
            print(f"Error saving private key: {e}")

        try:
            if save_csr:
                with open(self.csr_file, "wb") as f:
                    f.write(self.csr.public_bytes(serialization.Encoding.PEM))
                saved_csr = True
        except Exception as e:
            print(f"Error saving CSR: {e}")

        try:
            if save_cert:
                with open(self.certificate_file, "wb") as f:
                    f.write(self.certificate.public_bytes(serialization.Encoding.PEM))
                saved_certificate = True
        except Exception as e:
            print(f"Error saving certificate: {e}")

        return (saved_private, saved_csr, saved_certificate)

    def get_certificate(self) -> x509.Certificate:
        """Get the certificate."""
        return self.certificate

    def set_certificate(self, certificate: x509.Certificate):
        """Set the certificate."""
        self.certificate = certificate

    def get_csr(self) -> x509.CertificateSigningRequest:
        """Get the certificate signing request."""
        return self.csr
