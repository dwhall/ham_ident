import unittest
import os
import os.path

from ham_ident import HamIdentity, HamIdentityError, HamCredentialBuilder, HamCredential, HamCredentialError, HamJsonCredential


APP_NAME = "ham_ident_test"

class TestBuilder(unittest.TestCase):
    def tearDown(self):
        for tail in ("_cert.pem", "_cred.json", "_prv.pem", "_pub.der"):
            fn = os.environ["APPDATA"] + "\\ham_ident\\EX4MPL" + tail
            if os.path.exists(fn):
                os.remove(fn)

    def test_gen_person_creds(self):
        ident = HamIdentity(commonName="Alice",
                            emailAddress="alice@example.com",
                            pseudonym="EX4MPL")
        cred = HamCredentialBuilder.gen_personal_credentials(ident, b"pass")
        self.assertTrue(os.path.exists(os.environ["APPDATA"] + "\\ham_ident\\EX4MPL_cert.pem"))
        self.assertTrue(os.path.exists(os.environ["APPDATA"] + "\\ham_ident\\EX4MPL_cred.json"))
        self.assertTrue(os.path.exists(os.environ["APPDATA"] + "\\ham_ident\\EX4MPL_prv.pem"))
        self.assertTrue(os.path.exists(os.environ["APPDATA"] + "\\ham_ident\\EX4MPL_pub.der"))

    def test_gen_person_creds_full(self):
        ident = HamIdentity(commonName="Alice",
                            emailAddress="alice@example.com",
                            pseudonym="EX4MPL",
                            stateOrProvinceName="ST",
                            postalCode="12345",
                            countryName="US")
        cred = HamCredentialBuilder.gen_personal_credentials(ident, b"pass")
        self.assertTrue(os.path.exists(os.environ["APPDATA"] + "\\ham_ident\\EX4MPL_cert.pem"))
        self.assertTrue(os.path.exists(os.environ["APPDATA"] + "\\ham_ident\\EX4MPL_cred.json"))
        self.assertTrue(os.path.exists(os.environ["APPDATA"] + "\\ham_ident\\EX4MPL_prv.pem"))
        self.assertTrue(os.path.exists(os.environ["APPDATA"] + "\\ham_ident\\EX4MPL_pub.der"))


class TestCred(unittest.TestCase):
    def test_exists(self):
        self.assertFalse(HamCredential.exists("B0GUS"))

        self.assertFalse(HamJsonCredential.exists("B0GUS"))

    def test_get_fn(self):
        fn = HamCredential.get_fn("EX4MPL")
        self.assertTrue(len(fn) > 0)
        self.assertTrue(fn.endswith(HamCredential.CERT_TAIL))

        fn = HamJsonCredential.get_fn("EX4MPL")
        self.assertTrue(len(fn) > 0)
        self.assertTrue(fn.endswith(HamJsonCredential.JSON_TAIL))

    def test_get_ident_fail(self):
        with self.assertRaises(HamCredentialError):
            cred = HamCredential.get_ident("B0GUS")

        with self.assertRaises(HamCredentialError):
            cred = HamJsonCredential.get_ident("B0GUS")


if __name__ == '__main__':
    unittest.main()
