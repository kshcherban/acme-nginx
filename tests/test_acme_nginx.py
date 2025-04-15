import unittest
import os
import tempfile
import shutil
import logging
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
# from cryptography.hazmat.primitives import hashes

# Assuming your classes are importable like this
# Make sure acme_nginx is in your PYTHONPATH or installed
from acme_nginx.AcmeV2 import AcmeV2

log = logging.getLogger("acme_test")


class TestAcmeV2StagingIntegration(unittest.TestCase):
    """
    Integration tests for AcmeV2 against the LE Staging API.
    Uses real network calls and real filesystem operations in a temp dir.
    """

    def setUp(self):
        """Create a temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp()
        self.account_key_path = os.path.join(self.test_dir, "account.key")
        # register_account also creates the domain key, so provide a path
        self.domain_key_path = os.path.join(self.test_dir, "domain.key")
        self.cert_path = os.path.join(self.test_dir, "cert.pem")
        # Ensure paths don't exist before test
        if os.path.exists(self.account_key_path):
            os.remove(self.account_key_path)
        if os.path.exists(self.domain_key_path):
            os.remove(self.domain_key_path)

    def tearDown(self):
        """Remove the temporary directory and its contents."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_register_account_staging(self):
        """
        Test registering a new account with the Let's Encrypt staging API.
        """
        staging_api_url = "https://acme-staging-v02.api.letsencrypt.org/directory"

        # Instantiate AcmeV2 - Use dummy paths for cert/vhost as they aren't needed for registration
        acme_v2 = AcmeV2(
            api_url=staging_api_url,
            logger=log,
            domains=[
                "dummy.com"
            ],  # Need at least one domain for init, though not used here
            account_key=self.account_key_path,
            domain_key=self.domain_key_path,
            cert_path=os.path.join(self.test_dir, "dummy.pem"),  # Dummy path
            vhost=os.path.join(self.test_dir, "dummy.conf"),  # Dummy path
            skip_nginx_reload=True,  # Important to avoid trying to reload nginx
            debug=False,
        )

        # --- Action: Call the register_account method ---
        # This will create the account key file and make network calls
        directory = None
        try:
            directory = acme_v2.register_account()
        except Exception as e:
            # Catch potential network or API errors during the test
            self.fail(f"acme_v2.register_account() raised an exception: {e}")

        # --- Assertions ---
        # 1. Check that the account key file was created
        self.assertTrue(
            os.path.exists(self.account_key_path), "Account key file was not created."
        )
        # Optional: Check file content basic structure
        with open(self.account_key_path, "r") as f:
            key_content = f.read()
            self.assertIn("-----BEGIN PRIVATE KEY-----", key_content)

        # 2. Check that the domain key file was created (register_account calls create_key for it)
        self.assertTrue(
            os.path.exists(self.domain_key_path), "Domain key file was not created."
        )

        # 3. Check the returned directory object
        self.assertIsNotNone(directory, "Directory object should not be None.")
        self.assertIsInstance(directory, dict, "Directory should be a dictionary.")

        # 4. Check for essential keys returned by the ACME directory endpoint
        self.assertIn("newNonce", directory)
        self.assertIn("newAccount", directory)
        self.assertIn("newOrder", directory)
        # Add other keys you expect from the staging directory if needed

        # 5. Check that the account ID (kid) was added to the directory object
        self.assertIn(
            "_kid", directory, "Account ID (_kid) not found in directory object."
        )
        self.assertIsNotNone(directory["_kid"], "Account ID (_kid) should not be None.")
        self.assertTrue(
            directory["_kid"].startswith(
                "https://acme-staging-v02.api.letsencrypt.org/acme/acct/"
            ),
            f"Account ID (_kid) '{directory['_kid']}' does not look like a valid staging account URL.",
        )

    def test_create_csr(self):
        """
        Test creating a Certificate Signing Request (CSR).
        This reuses account and domain keys if they exist.
        """
        staging_api_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
        domain = "dummy.com"

        # Create AcmeV2 instance for the test
        acme_v2 = AcmeV2(
            api_url=staging_api_url,
            logger=log,
            domains=[domain, "www." + domain],
            account_key=self.account_key_path,
            domain_key=self.domain_key_path,
            cert_path=self.cert_path,
            vhost=os.path.join(self.test_dir, "dummy.conf"),
            skip_nginx_reload=True,
            debug=False,
        )

        # Ensure we have the domain key created first
        # If account key doesn't exist, register_account will create both
        if not os.path.exists(self.account_key_path):
            acme_v2.register_account()
        elif not os.path.exists(self.domain_key_path):
            acme_v2.create_key(self.domain_key_path)

        # Generate CSR
        csr = acme_v2.create_csr()

        # Verify the CSR
        self.assertIsNotNone(csr)
        self.assertGreater(len(csr), 0)

        # Parse the CSR to validate its structure
        csr_obj = x509.load_der_x509_csr(csr)
        self.assertIsInstance(csr_obj, x509.CertificateSigningRequest)

        # Check if the Common Name matches our domain
        common_names = csr_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        self.assertEqual(len(common_names), 1)
        self.assertEqual(common_names[0].value, domain)

        # Check for SAN extension with our domain
        san_found = False
        for extension in csr_obj.extensions:
            if extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                san = extension.value
                domain_found_in_san = False
                www_domain_found_in_san = False
                for name in san:
                    if name.value == domain:
                        domain_found_in_san = True
                    elif name.value == "www." + domain:
                        www_domain_found_in_san = True
                self.assertTrue(
                    domain_found_in_san, f"Domain {domain} not found in SAN extension"
                )
                self.assertTrue(
                    www_domain_found_in_san,
                    f"Domain www.{domain} not found in SAN extension",
                )
                san_found = True
                break

        self.assertTrue(san_found, "CSR should contain a SAN extension")

        # Verify that the CSR is properly signed (will raise an exception if invalid)
        # public_key = csr_obj.public_key()
        self.assertTrue(csr_obj.is_signature_valid, "CSR signature should be valid")


if __name__ == "__main__":
    unittest.main()
