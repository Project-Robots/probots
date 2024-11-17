""" Robots CLI for managing certificates. """
import click
from probots.security.x509 import X509Certificate

@click.group()
def cli():
    """ProBots CLI for managing certificates."""
    pass

@click.command()
@click.option('--common-name', required=True, help='Common Name for the certificate.')
@click.option('--subject-alt-names', multiple=True, help='Subject Alternative Names for the certificate.')
@click.option('--private-key-path', required=True, help='Path to save the private key.')
@click.option('--csr-path', required=True, help='Path to save the CSR.')
@click.option('--certificate-path', required=True, help='Path to save the certificate.')
def create_certificate(common_name, subject_alt_names, private_key_path, csr_path, certificate_path):
    """Create a new X509 certificate."""
    subject_oids = {"COMMON_NAME": common_name}
    cert = X509Certificate(subject_oids, list(subject_alt_names))
    
    # Create CSR
    csr = cert.create_csr()
    
    # Save private key and CSR
    cert.save_private_key(private_key_path)
    cert.save_csr(csr_path)
    
    click.echo(f"Private key saved to {private_key_path}")
    click.echo(f"CSR saved to {csr_path}")

    # Here you would typically call a CA to sign the CSR and get a certificate
    # For demonstration, we will just echo a message
    click.echo("Certificate signing process would be initiated here.")

@click.command()
@click.option('--private-key-path', required=True, help='Path to the CA private key.')
@click.option('--public-key-path', required=True, help='Path to the CA public key.')
@click.option('--csr-path', required=True, help='Path to the CSR to sign.')
@click.option('--certificate-path', required=True, help='Path to save the signed certificate.')
def sign_certificate(private_key_path, public_key_path, csr_path, certificate_path):
    """Sign a CSR and generate a certificate."""
    from probots.security.ca import CertificateAuthority

    ca = CertificateAuthority(private_key_file=private_key_path, public_key_file=public_key_path)

    with open(csr_path, 'rb') as f:
        csr_data = f.read()

    signed_certificate = ca.sign_csr(csr_data)

    with open(certificate_path, 'wb') as cert_file:
        cert_file.write(signed_certificate)

    click.echo(f"Signed certificate saved to {certificate_path}")

@click.command()
@click.option('--certificate-path', required=True, help='Path to the certificate to delete.')
def delete_certificate(certificate_path):
    """Delete a certificate."""
    import os

    if os.path.exists(certificate_path):
        os.remove(certificate_path)
        click.echo(f"Certificate deleted: {certificate_path}")
    else:
        click.echo(f"Certificate not found: {certificate_path}")

cli.add_command(create_certificate)
cli.add_command(sign_certificate)
cli.add_command(delete_certificate)

if __name__ == '__main__':
    cli()

cli.add_command(create_certificate)

if __name__ == '__main__':
    cli()
