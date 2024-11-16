import os
import pwd
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import pytz # Import pytz for timezone handling
import socket

def get_default_paths(robot_name="robot", hostname=socket.gethostname()):
  """Determine default paths based on the user privilege level."""
  if os.geteuid() == 0:  # Check if the user is root
      base_path = f"/etc/{robot_name}/ssl/"
  else:
      base_path = os.path.expanduser(f"~/.{robot_name}/ssl/")
  
  return {
      "private_key_path": os.path.join(base_path, f"{hostname}_key.pem"),
      "certificate_path": os.path.join(base_path, f"{hostname}_cert.pem"),
      "csr_path": os.path.join(base_path, f"{hostname}_csr.pem"),
  }
    
class HostCertificate(BaseModel):
    cert_path: str = Field(default=None,
                         description="Path to the host certificate")
  
    key_path: str = Field(default=None,
                        description="Path to the host private key")
  
    csr_path: str = Field(default=None,
                        description="Path to the host CSR")
  
    robot_name: str = Field(default="robot",
                          description="Name of the robot or application")
  
    country: str = Field(default="US",
                       description="Country Name (2 letter code)")
  
    state: str = Field(default="California",
                     description="State or Province Name (full name)")
  
    locality: str = Field(default="Placentia",
                        description="Locality Name (eg, city)")
  
    organization: str = Field(default="Project Robots | Thought Parameters LLC",
                            description="Organization Name (eg, company)")
  
    organizational_unit: str = Field(default="Engineering",
                                   description="Organizational Unit (eg, section)")
  
    common_name: str = Field(default=f"{str(socket.gethostname())}.io.bot",
                           description="Common Name (e.g., server FQDN or YOUR name)")
  
    alt_names: list[str] = Field(default_factory=lambda: [str(socket.gethostname()), str(socket.getfqdn())],
                               description="Subject Alternative Names")

    private_key: str = Field(default=None,
                             description="Private Key")
    
    certificate: str = Field(default=None,
                             description="Certificate")
    
    csr: str = Field(default=None,
                    description="Certificate Signing Request")
    
    def __init__(self, **data):
        """
        Initialize the HostCertificate instance.

        This constructor initializes the HostCertificate instance by setting
        the certificate, key, and CSR paths based on default values or provided
        data. It also initializes private key, certificate, and CSR attributes
        to None. Paths are determined using the robot's name and hostname,
        ensuring appropriate file locations for SSL-related files.

        Args:
            **data: Arbitrary keyword arguments for initializing field values.
        """
        super().__init__(**data)
        paths = get_default_paths(self.robot_name, hostname=self.common_name)
        self.cert_path = self.cert_path or paths["certificate_path"]
        self.key_path = self.key_path or paths["private_key_path"]
        self.csr_path = self.csr_path or paths["csr_path"]

    def generate_key_and_csr(self):
        """
        Generates a private key and certificate signing request (CSR) for a host.

        This method generates a new private key and CSR for a host based on the
        subject information provided. The private key and CSR are saved to the
        key and CSR paths specified in the constructor, respectively.

        Returns:
            None
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Create CSR
        subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, self.country),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, self.state),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, self.locality),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, self.organization),
        x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, self.organizational_unit),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, self.common_name),
        ])
        self.csr = x509.CertificateSigningRequestBuilder().subject_name(subject).add_extension(
            x509.SubjectAlternativeName([
            x509.DNSName(name) for name in self.alt_names
        ]), critical=False).sign(
            private_key=self.private_key, rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), algorithm=hashes.SHA256()
        )

        # Save private key and CSR
        os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
        
        with open(self.key_path, "wb") as key_file:
            key_file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        with open(self.csr_path, "wb") as csr_file:
            csr_file.write(self.csr.public_bytes(serialization.Encoding.PEM))

    def save_certificate(self, certificate: x509.Certificate):
        """
        Save a certificate to the given path.

        Args:
            certificate (x509.Certificate): The certificate to save.

        Returns:
            None
        """
        os.makedirs(os.path.dirname(self.cert_path), exist_ok=True)
        
        with open(self.cert_path, "wb") as cert_file:
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
            
    def load_or_generate(self):
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )

        if os.path.exists(self.cert_path):
            with open(self.cert_path, "rb") as cert_file:
                self.certificate = x509.load_pem_x509_certificate(
                    cert_file.read(),
                    backend=default_backend()
                )
        
        if os.path.exists(self.csr_path):
            with open(self.csr_path, "rb") as csr_file:
                self.csr = x509.load_pem_x509_csr(csr_file.read(), default_backend())

            return self.csr, self.certificate # Return the CSR
        else:
            self.generate_key_and_csr()
            return self.csr, None # Return the CSR
        
    def get_certificate(self):
        if self.certificate is None:
            raise ValueError("Certificate not loaded or generated.")
        return self.certificate