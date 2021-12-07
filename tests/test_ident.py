import unittest

from ham_ident import Identity, IdentityError, HamIdentity


class TestIdentity(unittest.TestCase):
    def test_ctor_exception(self):
        with self.assertRaises(IdentityError):
            i = Identity()

    def test_ctor(self):
        i = Identity(givenName="Given", emailAddress="given@example.com")

    def test_surname_exception(self):
        with self.assertRaises(IdentityError):
            i = Identity(surname="Last")

    def test_surname(self):
        i = Identity(givenName="Given", emailAddress="given@example.com", surname="Last")

    def test_pseudonym_exception(self):
        with self.assertRaises(IdentityError):
            i = Identity(pseudonym="EX4MPL")

    def test_pseudonym_exception_(self):
        with self.assertRaises(IdentityError):
            i = Identity(givenName="Given", emailAddress="given@example.com", pseudonym="EX4MPL")

    def test_attr_empty(self):
        i = Identity(givenName="Given", emailAddress="given@example.com", surname="Last")
        self.assertEquals(i.countryName, "")

    def test_attr(self):
        i = Identity(givenName="Given", emailAddress="given@example.com", surname="Last")
        self.assertEqual(i.givenName, "Given")

    def test_all(self):
        i = Identity(
            givenName="Given",
            surname="Last",
            emailAddress="given@example.com",
            stateOrProvinceName="ST",
            countryName="US",
            postalCode="12345"
        )
        self.assertEqual(i.givenName, "Given")
        self.assertEqual(i.surname, "Last")
        self.assertEqual(i.emailAddress, "given@example.com")
        self.assertEqual(i.stateOrProvinceName, "ST")
        self.assertEqual(i.countryName, "US")
        self.assertEqual(i.postalCode, "12345")


class TestHamIdentity(unittest.TestCase):
    def test_ctor_exception(self):
        with self.assertRaises(IdentityError):
            h = HamIdentity()

    def test_ctor(self):
        h = HamIdentity(givenName="Given", emailAddress="given@example.com")

    def test_surname_exception(self):
        with self.assertRaises(IdentityError):
            h = HamIdentity(surname="Last")

    def test_surname(self):
        h = HamIdentity(givenName="Given", emailAddress="given@example.com", surname="Last")

    def test_pseudonym_exception(self):
        with self.assertRaises(IdentityError):
            h = HamIdentity(pseudonym="EX4MPL")

    def test_pseudonym(self):
        h = HamIdentity(givenName="Given", emailAddress="given@example.com", pseudonym="EX4MPL")

    def test_attr_empty(self):
        h = HamIdentity(givenName="Given", emailAddress="given@example.com", surname="Last")
        self.assertEquals(h.countryName, "")

    def test_attr(self):
        h = HamIdentity(givenName="Given", emailAddress="given@example.com", surname="Last")
        self.assertEqual(h.givenName, "Given")

    def test_all(self):
        h = HamIdentity(
            givenName="Given",
            surname="Last",
            emailAddress="given@example.com",
            stateOrProvinceName="ST",
            countryName="US",
            postalCode="12345",
            pseudonym="EX4MPL"
        )
        self.assertEqual(h.givenName, "Given")
        self.assertEqual(h.surname, "Last")
        self.assertEqual(h.emailAddress, "given@example.com")
        self.assertEqual(h.stateOrProvinceName, "ST")
        self.assertEqual(h.countryName, "US")
        self.assertEqual(h.postalCode, "12345")
        self.assertEqual(h.pseudonym, "EX4MPL")


if __name__ == '__main__':
    unittest.main()
