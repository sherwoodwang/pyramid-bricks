import copy
import requests

import json
import time
from jwt.jwt import JWT
from jwt.jwk import JWKSet

proxies = {
        "https": "http://172.16.0.1:37269"
        }

default_id_classes = {}

class OAuthException(RuntimeError):
    pass

class OAuthIdentity:
    name = "default"

    def __init__(self, config, data):
        """Constructor

        :param OAuthConfig config: the OAuthConfig which constructs this object
        :param dict data: the token returned by OAuth provider
        """

        if "error" in data:
            raise OAuthException(data["error"], data["error_description"])

        self.data = data
        self.config = config
        self.access_token = self.data["access_token"]
        self.expires_in = self.data["expires_in"]
        self.token_type = self.data["token_type"]

        if "refresh_token" in self.data:
            self.refresh_token = self.data["refresh_token"]
        else:
            self.refresh_token = None

    @classmethod
    def register(cls, id_classes = default_id_classes):
        id_classes[cls.name] = cls

OAuthIdentity.register()

class JWTBasedOAuthIdentity(OAuthIdentity):
    @classmethod
    def __refresh_keyset(cls):
        """Refresh __cached_keset with new value if the old one is expired.

        __cached_keset is JWT public keyset from the OAuth provider. The JWT
        keyset content is the return value of _fetch_keyset_cert(), which
        should be fetched through a secure channel.
        """

        try:
            cls.__cached_keyset
        except AttributeError:
            cls.__cached_keyset = None 

        if cls.__cached_keyset is None or cls.__cached_keyset_exp < time.time():
            cert, exp = cls._fetch_keyset_cert()
            cls.__cached_keyset_exp = exp
            cls.__cached_keyset = JWKSet.from_dict(json.loads(cert))
            cls.jwt = JWT(cls.__cached_keyset)

    @staticmethod
    def _fetch_keyset_cert():
        raise NotImplementedError()

    def __init__(self, config, data):
        super().__init__(config, data)
        self.__refresh_keyset()
        self.id_token = json.loads(self.jwt.decode(data["id_token"]).decode("utf-8"))
        if self.id_token["aud"] != self.config.client_id:
            raise OAuthException("#audience not match",
                    "Audience of the issued token is not this application")

class GoogleOAuthIdentity(JWTBasedOAuthIdentity):
    name = "google"

    @staticmethod
    def _fetch_keyset_cert():
        return (requests.get("https://www.googleapis.com/oauth2/v2/certs",
            proxies = proxies).text, time.time() + 24 * 60 * 60)

    def __init__(self, config, data):
        super().__init__(config, data)
        if self.id_token["iss"] != "accounts.google.com":
            raise OAuthException("#unknown issuer",
                    "Issuer of the token must be Google")
        self.subject = self.id_token['sub']

GoogleOAuthIdentity.register()

class OAuthConfig:
    def __init__(self):
        self.authentication_endpoint = None
        self.token_endpoint = None
        self.client_id = None
        self.email_address = None
        self.client_secret = None
        self.redirect_uri = None
        self.javascript_origins = None
        self.id_class = OAuthIdentity

    def get_token_by_code(self, authorization_code):
        """Fetch the OAuth token, the token is returned as an instance of
        self.id_class.

        Request the OAuth provider with code to get the token, then parse the
        token and use it to construct the id to return.

        :returns: an instance of self.id_class
        """

        data = {
                "code": authorization_code,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "redirect_uri": self.redirect_uri,
                "grant_type": "authorization_code",
                }
        return self.id_class(self, json.loads(requests.post(self.token_endpoint, 
            data, proxies = proxies).text))

    def get_token(self, request):
        """Fetch the OAuth token with the code in Pyramid request object.

        Conceptually: return self.get_token_by_code(request.params["code"]).
        It's the caller's responsibility to verify CSRF token.

        :returns: an instance of self.id_class
        """

        if "error" in request.params:
            raise Exception(request.params["error"])
        return self.get_token_by_code(request.params["code"])

    @staticmethod
    def factory(request):
        return request.registry._oauth_config

def configure_oauth(config, settings, id_classes = default_id_classes):
    """Configure Pyramid config object with settings

    Setting strings starting with ``oauth.'' will be analyzed.
    registry._oauth_config will be generated as a dictionary. The second part
    of setting entries is the provider, which will be the key of
    registry._oauth_config. The value in the dictionary will be the OAuthConfig
    object containing your settings. ``oauth.<provider>.id_class'' will be
    looked up in id_classes.

    OAuthConfig.factory is a simple factory returns registry._oauth_config.

    Example:
        Settings::
            oauth.google.id_class = google
            oauth.google.authentication_endpoint = https://accounts.google.com/o/oauth2/auth
            oauth.google.token_endpoint = https://accounts.google.com/o/oauth2/token
            oauth.google.client_id = XXX.apps.googleusercontent.com
            oauth.google.email_address = XXX@developer.gserviceaccount.com
            oauth.google.client_secret = XXX
            oauth.google.redirect_uri = http://mysite/oauth2callback/google
            oauth.google.javascript_origins = http://mysite

        Configuring code::
            config = Configurator(settings=settings)
            config.include('pyramid_bricks.oauth')
            config.add_route('oauth2callback', '/oauth2callback/*traverse',
                    factory = OAuthConfig.factory)

        Callback View code::
            @view_config(route_name = 'oauth2callback', context = OAuthConfig)
            def oauth2callback(request):
                state = json.loads(request.params["state"])
                if request.session.get_csrf_token() != state['csrf_token']:
                    raise BadCSRFToken()
                identity = request.context.get_token(request)
                # identity is a GoogleOAuthIdentity object
                ...
    """
    ocs = {}
    for name in settings:
        if name.startswith("oauth."):
            comps = name.split('.')
            provider = comps[1]
            attribute = comps[2]
            value = settings[name]
            if attribute == "id_class":
                value = id_classes[value]
            if provider not in ocs:
                ocs[provider] = OAuthConfig()
            setattr(ocs[provider], attribute, value)
    config.registry._oauth_config = ocs

def includeme(config):
    configure_oauth(config, config.registry.settings)

# vim: ts=4 sw=4 et nu
