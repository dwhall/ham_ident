import unittest

from ham_ident import HamCredential, HamCredentialError, HamJsonCredential


APP_NAME = "ham_ident_test"

class TestCred(unittest.TestCase):
    def test_exists(self):
        self.assertFalse(HamCredential.exists(APP_NAME, "B0GUS"))

        self.assertFalse(HamJsonCredential.exists(APP_NAME, "B0GUS"))

    def test_get_fn(self):
        fn = HamCredential.get_fn(APP_NAME, "EX4MPL")
        self.assertTrue(len(fn) > 0)
        self.assertTrue(fn.endswith(HamCredential.FN_TAIL))

        fn = HamJsonCredential.get_fn(APP_NAME, "EX4MPL")
        self.assertTrue(len(fn) > 0)
        self.assertTrue(fn.endswith(HamJsonCredential.FN_TAIL))

    def test_get_ident_fail(self):
        with self.assertRaises(HamCredentialError):
            cred = HamCredential.get_ident(APP_NAME, "B0GUS")

        with self.assertRaises(HamCredentialError):
            cred = HamJsonCredential.get_ident(APP_NAME, "B0GUS")

if __name__ == '__main__':
    unittest.main()
