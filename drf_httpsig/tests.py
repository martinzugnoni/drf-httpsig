from datetime import datetime, timedelta

from freezegun import freeze_time
from django.test import SimpleTestCase, TestCase, RequestFactory
from django.contrib.auth import get_user_model
from drf_httpsig.authentication import SignatureAuthentication
from rest_framework.exceptions import AuthenticationFailed


User = get_user_model()

ENDPOINT = '/api'
METHOD = 'GET'
KEYID = 'some-key'
SECRET = 'my secret string'
SIGNATURE = 'some.signature'


def build_signature(headers, key_id=KEYID, signature=SIGNATURE):
    """Build a signature string."""
    template = ('Signature keyId="%(keyId)s",algorithm="hmac-sha256",'
                'headers="%(headers)s",signature="%(signature)s"')
    return template % {
        'keyId': key_id,
        'signature': signature,
        'headers': ' '.join(headers),
    }


class SignatureAuthenticationTestCase(TestCase):

    class APISignatureAuthentication(SignatureAuthentication):
        """Extend the SignatureAuthentication to test it."""

        def __init__(self, user):
            self.user = user

        def fetch_user_data(self, keyid, algorithm=None):
            if keyid != KEYID:
                raise AuthenticationFailed('Bad key ID')

            return (self.user, SECRET)

        def fetch_on_behalf_of_user(self, user_id):
            return self.user

    TEST_USERNAME = 'test-user'
    TEST_PASSWORD = 'test-password'

    def setUp(self):
        User.objects.create(username=self.TEST_USERNAME)
        self.test_user = User.objects.get(username=self.TEST_USERNAME)
        self.test_user.set_password(self.TEST_PASSWORD)
        self.auth = self.APISignatureAuthentication(self.test_user)

    def test_missing_authorization(self):
        """
        Return None on missing Authorization header.
        """
        request = RequestFactory().get(ENDPOINT)
        res = self.auth.authenticate(request)
        self.assertIsNone(res)

    def test_foreign_authorization(self):
        """
        Return None on unknown Authorization header.
        """
        request = RequestFactory().get(ENDPOINT, {}, HTTP_AUTHORIZATION='NotSignature some-relevant-argument')
        res = self.auth.authenticate(request)
        self.assertIsNone(res)

    def test_bad_signature_1(self):
        """
        Raise AuthenticationFailed on malformed Authorization header.
        """
        request = RequestFactory().get(ENDPOINT, {}, HTTP_AUTHORIZATION='Signature some-wrong-value')
        self.assertRaises(AuthenticationFailed, self.auth.authenticate, request)

    def test_bad_signature_2(self):
        """
        Raise AuthenticationFailed when missing algorithm argument.
        """
        request = RequestFactory().get(ENDPOINT, {}, HTTP_AUTHORIZATION='Signature keyId=foobar,signature=nope')
        self.assertRaises(AuthenticationFailed, self.auth.authenticate, request)

    def test_bad_signature_3(self):
        """
        Raise AuthenticationFailed when missing keyId argument.
        """
        request = RequestFactory().get(ENDPOINT, {}, HTTP_AUTHORIZATION='Signature signature=nope,algorithm="hmac-sha256"')
        self.assertRaises(AuthenticationFailed, self.auth.authenticate, request)

    def test_bad_signature_4(self):
        """
        Raise AuthenticationFailed when missing signature argument.
        """
        request = RequestFactory().get(ENDPOINT, {}, HTTP_AUTHORIZATION='Signature KeyId=foobar,algorithm="hmac-sha256"')
        self.assertRaises(AuthenticationFailed, self.auth.authenticate, request)

    def test_invalid_signature(self):
        """
        Same test as `valid` but with the headers in a different order.
        """
        headers = ['(request-target)', 'accept', 'host', 'date']
        expected_signature = 'SelruOP39OWoJrSopfYJ99zOLoswmpyGXyDPdebeELc='

        expected_signature_string = build_signature(
            headers,
            key_id=KEYID,
            signature=expected_signature)

        request = RequestFactory().get(
            '/packages/measures/', {},
            HTTP_HOST='localhost:8000',
            HTTP_DATE='Mon, 17 Feb 2014 06:11:05 GMT',
            HTTP_ACCEPT='application/json',
            HTTP_AUTHORIZATION=expected_signature_string)

        self.assertRaises(AuthenticationFailed, self.auth.authenticate, request)

    def test_valid_signature(self):
        """
        A perfectly valid signature.
        """
        headers = ['(request-target)', 'accept', 'date', 'host']
        expected_signature = 'SelruOP39OWoJrSopfYJ99zOLoswmpyGXyDPdebeELc='
        expected_signature_string = build_signature(
            headers,
            key_id=KEYID,
            signature=expected_signature)
        request = RequestFactory().get(
            '/packages/measures/', {},
            HTTP_HOST='localhost:8000',
            HTTP_DATE='Mon, 17 Feb 2014 06:11:05 GMT',
            HTTP_ACCEPT='application/json',
            HTTP_AUTHORIZATION=expected_signature_string)

        result = self.auth.authenticate(request)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], self.test_user)

    @freeze_time("2020-02-15")
    def test_expired_signature(self):
        """
        Should fail authentication with signature is expired.
        """
        headers = ['(request-target)', '(expires)', 'accept', 'date', 'host']
        expected_signature = 'gQew3jrn38XfSVXi2nJ5E6AZOrrZm17rWnNiSlFZRhs='
        expected_signature_string = build_signature(
            headers,
            key_id=KEYID,
            signature=expected_signature)
        headers = {
            'HTTP_HOST': 'localhost:8000',
            'HTTP_DATE': 'Mon, 17 Feb 2014 06:11:05 GMT',
            'HTTP_ACCEPT': 'application/json',
            'HTTP_(expires)': '1577847600',  # 2020-01-01
            'HTTP_AUTHORIZATION': expected_signature_string,
        }
        request = RequestFactory().get('/packages/measures/', {}, **headers)
        with self.assertRaises(AuthenticationFailed):
            self.auth.authenticate(request)

    def test_valid_signature_on_behalf_of_other_user(self):
        """
        A perfectly valid signature requesting on behalf of other user.
        """
        headers = ['(request-target)', 'accept', 'date', 'host']
        expected_signature = 'SelruOP39OWoJrSopfYJ99zOLoswmpyGXyDPdebeELc='
        expected_signature_string = build_signature(
            headers,
            key_id=KEYID,
            signature=expected_signature)
        request = RequestFactory().get(
            '/packages/measures/', {},
            HTTP_HOST='localhost:8000',
            HTTP_DATE='Mon, 17 Feb 2014 06:11:05 GMT',
            HTTP_ACCEPT='application/json',
            HTTP_AUTHORIZATION=expected_signature_string,
            HTTP_ON_BEHALF_OF=str(self.test_user.id))

        result = self.auth.authenticate(request)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], self.test_user)
        self.assertEqual(result[1], None)
