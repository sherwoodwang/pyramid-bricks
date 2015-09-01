from .._core import JWTBasedOAuthIdentity
import requests
import time

class GoogleOAuthIdentity(JWTBasedOAuthIdentity):
    name = "google"
    config = {
            'authentication_endpoint': 'https://accounts.google.com/o/oauth2/auth',
            'token_endpoint': 'https://accounts.google.com/o/oauth2/token'
            }

    @staticmethod
    def _fetch_keyset_cert():
        return (requests.get("https://www.googleapis.com/oauth2/v2/certs").text, time.time() + 24 * 60 * 60)

    def __init__(self, config, status_code, data):
        super().__init__(config, status_code, data)
        if self.id_token["iss"] != "accounts.google.com":
            raise OAuthException("#unknown issuer",
                    "Issuer of the token must be Google")
        self.subject = self.id_token['sub']

GoogleOAuthIdentity.register()

# vim: ts=4 sw=4 et nu
