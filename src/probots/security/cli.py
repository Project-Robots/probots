""" CLI for managing and interacting with certificates for Project Robots. """
import click
from probots.security.ca import CertificateAuthority
from probots.security.cert import HostCertificate
from probots.security.store import CertificateStore
from cryptography import x509
import os

@click.group()
def cli():
    """CLI for managing and interacting with certificates for ProBots."""
    pass

@click.command()
@click.option('--country', default='US', help='Country Name (2 letter code)')
@click.option('--state', default='California', help='State or Province Name (full name)')
@click.option('--locality', default='Placentia', help='Locality Name (e.g., city)')
@click.option('--organization', default='Project Robots | Thought Parameters LLC', help='Organization Name (e.g., company)')
@click.option('--organizational_unit', default='Engineering', help='Organizational Unit (e.g., section)')
@click.option('--common_name', default='orbit.local', help='Common Name (e.g., server FQDN or YOUR name)')
@click.option('--robot_name', default='orbit', help='Robot name to set for default paths. Default: orbit')
def init_ca(country, state, locality, organization, organizational_unit, common_name, robot_name):
    """Initialize the Certificate Authority (CA)."""
    ca = CertificateAuthority(
        country=country,
        state=state,
        locality=locality,
        organization=organization,
        organizational_unit=organizational_unit,
        common_name=common_name,
        robot_name=robot_name
    )
    ca._generate_ca()
    click.echo("Certificate Authority initialized successfully.")

@click.command()
@click.option('--csr-path', required=True, help='Path to the Certificate Signing Request (CSR) file')
@click.option('--output', default='signed_cert.pem', help='Output path for the signed certificate')
@click.option('--robot_name', default='orbit', help='Robot name to set for default paths. Default: orbit')
def sign_csr(csr_path, output, robot_name):
    """Sign a Certificate Signing Request (CSR) with the CA."""
    ca = CertificateAuthority(robot_name=robot_name)
    with open(csr_path, 'rb') as csr_file:
        csr = x509.load_pem_x509_csr(csr_file.read())
    signed_cert = ca.sign_csr(csr)
    with open(output, 'wb') as cert_file:
        cert_file.write(signed_cert.public_bytes())
    click.echo(f"CSR signed and saved to {output}")

@click.command()
@click.option('--cert-path', required=True, help='Path to the certificate file to verify')
@click.option('--robot_name', default='orbit', help='Robot name to set for default paths. Default: orbit')
def verify_cert(cert_path, robot_name):
    """Verify a certificate with the CA."""
    ca = CertificateAuthority(robot_name=robot_name)
    with open(cert_path, 'rb') as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read())
    result = ca.verify_certificate(cert)
    click.echo(f"Certificate verification result: {'Valid' if result else 'Invalid'}")

@click.command()
@click.option('--host-name', required=True, help='Hostname for the certificate')
@click.option('--output-dir', default='.', help='Directory to save the key and CSR')
def generate_host_cert(host_name, output_dir):
    """Generate a private key and CSR for a host."""
    host_cert = HostCertificate(common_name=host_name)
    csr, _ = host_cert.load_or_generate()
    csr_path = os.path.join(output_dir, f"{host_name}_csr.pem")
    key_path = os.path.join(output_dir, f"{host_name}_key.pem")
    with open(csr_path, 'wb') as csr_file:
        csr_file.write(csr.public_bytes())
    with open(key_path, 'wb') as key_file:
        key_file.write(host_cert.private_key.private_bytes())
    click.echo(f"Generated CSR at {csr_path} and key at {key_path}")

@click.command()
@click.option('--cert-path', required=True, help='Path to the certificate file to add to the store')
@click.option('--robot_name', default='orbit', help='Robot name to set for default paths. Default: orbit')
def add_cert_to_store(cert_path, robot_name):
    """Add a certificate to the certificate store."""
    store = CertificateStore(robot_name=robot_name)
    with open(cert_path, 'rb') as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read())
    store.add_certificate(cert)
    click.echo(f"Certificate added to store at {store.store_path}")

@click.command()
@click.option('--robot_name', default='orbit', help='Robot name to set for default paths. Default: orbit')
def list_certificates(robot_name):
    """List all certificates in the store."""
    store = CertificateStore(robot_name=robot_name)
    certificates = store.load_certificates()
    if certificates:
        click.echo("Certificates in the store:")
        for subject, cert in certificates.items():
            click.echo(f"- {subject.rfc4514_string()} (Valid from {cert.not_valid_before_utc} to {cert.not_valid_after_utc})")
    else:
        click.echo("No certificates found in the store.")

# Add the commands to the CLI
cli.add_command(init_ca)
cli.add_command(sign_csr)
cli.add_command(verify_cert)
cli.add_command(generate_host_cert)
cli.add_command(add_cert_to_store)
cli.add_command(list_certificates)

# Run the CLI
if __name__ == '__main__':
    cli()