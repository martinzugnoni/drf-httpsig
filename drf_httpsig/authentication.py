import time

from rest_framework import authentication
from rest_framework import exceptions

from httpsig import HeaderVerifier, utils

"""
Reusing failure exceptions serves several purposes:

    1. Lack of useful information regarding the failure inhibits attackers
    from learning about valid keyIDs or other forms of information leakage.
    Using the same actual object for any failure makes preventing such
    leakage through mistakenly-distinct error messages less likely.

    2. In an API scenario, the object is created once and raised many times
    rather than generated on every failure, which could lead to higher loads
    or memory usage in high-volume attack scenarios.

"""
FAILED = exceptions.AuthenticationFailed("Invalid signature.")


class SignatureAuthentication(authentication.BaseAuthentication):
    """
    DRF authentication class for HTTP Signature support.

    You must subclass this class in your own project and implement the
    `fetch_user_data(self, keyId, algorithm)` method, returning a tuple of
    the User object and a bytes object containing the user's secret. Note
    that key_id and algorithm are DIRTY as they are supplied by the client
    and so must be verified in your subclass!

    You may set the following class properties in your subclass to configure
    authentication for your particular use case:

    :param www_authenticate_realm:  Default: "api"
    :param required_headers:        Default: ["(request-target)", "date"]
    """

    www_authenticate_realm = "api"
    required_headers = ["(request-target)", "date"]

    def fetch_user_data(self, keyId, algorithm=None):
        """Retuns a tuple (User, secret) or (None, None)."""
        raise NotImplementedError()

    def fetch_on_behalf_of_user(self, user_id):
        """Retuns the user object to be impersonated in the current request."""
        raise NotImplementedError()

    def authenticate_header(self, request):
        """
        DRF sends this for unauthenticated responses if we're the primary
        authenticator.
        """
        h = " ".join(self.required_headers)
        return 'Signature realm="%s",headers="%s"' % (self.www_authenticate_realm, h)

    def authenticate(self, request):
        """
        Perform the actual authentication.

        Note that the exception raised is always the same. This is so that we
        don't leak information about in/valid keyIds and other such useful
        things.
        """
        auth_header = authentication.get_authorization_header(request)
        if not auth_header or len(auth_header) == 0:
            return None

        method, fields = utils.parse_authorization_header(auth_header)

        # Ignore foreign Authorization headers.
        if method.lower() != "signature":
            return None

        # Verify basic header structure.
        if len(fields) == 0:
            raise FAILED

        # Ensure all required fields were included.
        if len(set(("keyid", "algorithm", "signature")) - set(fields.keys())) > 0:
            raise FAILED

        # Fetch the secret associated with the keyid
        user, secret = self.fetch_user_data(
            fields["keyid"], algorithm=fields["algorithm"]
        )

        if not (user and secret):
            raise FAILED

        # Verify headers
        hs = HeaderVerifier(
            request.headers,
            secret,
            required_headers=self.required_headers,
            method=request.method.lower(),
            path=request.get_full_path(),
        )

        # All of that just to get to this.
        if not hs.verify():
            raise FAILED

        # Check if the signature is expired
        expires = request.headers.get("(expires)", None)
        try:
            expires = int(expires)
        except TypeError:
            expires = None
        if expires and time.time() > expires:
            raise FAILED

        if 'On-Behalf-Of' in request.headers:
            user = self.fetch_on_behalf_of_user(request.headers['On-Behalf-Of'])
            if not user:
                raise exceptions.AuthenticationFailed("On behalf of user was not found.")
            return (user, None)

        return (user, fields["keyid"])
