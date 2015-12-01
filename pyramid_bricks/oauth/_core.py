from urllib.parse import urlparse, urlencode
from jwt.jwt import JWT
from jwt.jwk import JWKSet
from zope.interface import implementer, Interface
import json
import time
import requests

default_id_classes = {}


class OAuthException(RuntimeError):
    pass


class OAuthIdentity:
    name = "default"
    config = {}

    def __init__(self, config, status_code, data):
        """Constructor

        :param OAuthProviderConfig config: the OAuthProviderConfig which constructs this object
        :param dict data: the token returned by OAuth provider
        """

        if status_code not in [200, 400]:
            raise OAuthException('#http error', 'status code is {}'.format(status_code))

        if "error" in data:
            raise OAuthException(data["error"], data["error_description"])

        self.data = data
        self.config = config
        for attr in ["access_token", "expires_in", "token_type"]:
            if attr in self.data:
                setattr(self, attr, self.data[attr])
            else:
                setattr(self, attr, None)

        if "refresh_token" in self.data:
            self.refresh_token = self.data["refresh_token"]
        else:
            self.refresh_token = None

    @classmethod
    def register(cls, name=None, defconf=None, id_classes=default_id_classes):
        if name is None:
            name = cls.name
        if defconf is None:
            defconf = cls.config
        id_classes[name] = (cls, defconf)


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

    def __init__(self, config, status_code, data):
        super().__init__(config, status_code, data)
        self.__refresh_keyset()
        self.id_token = json.loads(self.jwt.decode(data["id_token"]).decode("utf-8"))
        if self.id_token["aud"] != self.config.client_id:
            raise OAuthException("#audience not match",
                                 "Audience of the issued token is not this application")


class OAuthProviderConfig:
    def __init__(self, name, callback_url_prefix):
        self.name = name
        self.callback_url_prefix = callback_url_prefix
        self.authentication_endpoint = None
        self.token_endpoint = None
        self.client_id = None
        self.client_secret = None
        self.id_class = OAuthIdentity

    def authorization_url(self, scope, state):
        param = {'client_id': self.client_id,
                 'response_type': 'code',
                 'redirect_uri': self.callback_url_prefix + self.name,
                 'scope': scope,
                 'state': state}
        ret = self.authentication_endpoint
        if ret.find('?') == -1:
            ret += '?'
        else:
            ret += '&'
        ret += urlencode(param)
        return ret

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
            "redirect_uri": self.callback_url_prefix + self.name,
            "grant_type": "authorization_code",
        }
        resp = requests.post(self.token_endpoint, data, headers={'user-agent': 'pyramid_bricks.oauth'})
        return self.id_class(self, resp.status_code, json.loads(resp.text) if resp.status_code in [200, 400] else None)

    def get_token(self, request):
        """Fetch the OAuth token with the code in Pyramid request object.

        Conceptually: return self.get_token_by_code(request.params["code"]).
        It's the caller's responsibility to verify CSRF token.

        :returns: an instance of self.id_class
        """

        if "error" in request.params:
            raise Exception(request.params["error"])
        return self.get_token_by_code(request.params["code"])


class IOAuthConfig(Interface):
    def add(self, provider_config: OAuthProviderConfig):
        pass

    def __setitem__(self, provider: str, provider_config: OAuthProviderConfig):
        pass

    def __getitem__(self, provider: str):
        pass

    def __contains__(self, provider: str):
        pass


@implementer(IOAuthConfig)
class OAuthConfig:
    def __init__(self):
        self._data = {}

    def add(self, provider_config: OAuthProviderConfig):
        self[provider_config.name] = provider_config

    def __setitem__(self, provider: str, provider_config: OAuthProviderConfig):
        self._data[provider] = provider_config

    def __getitem__(self, provider: str):
        return self._data[provider]

    def __contains__(self, provider: str):
        return provider in self._data


def configure_oauth2(config, settings, id_classes=default_id_classes):
    """Configure Pyramid config object with settings

    Example:
        Settings::
            oauth2callback = http://mysite/oauth2callback/
            oauth2.google.id_class = google
            oauth2.google.client_id = XXX.apps.googleusercontent.com
            oauth2.google.client_secret = XXX

        Configuring code::
            config = Configurator(settings=settings)
            config.include('pyramid_bricks.oauth')

        Callback View code::
            @view_config(route_name = 'oauth2callback', context = OAuthProviderConfig)
            def oauth2callback(request):
                state = json.loads(request.params["state"])
                if request.session.get_csrf_token() != state['csrf_token']:
                    raise BadCSRFToken()
                requests.session.new_csrf_token()
                # context is a OAuthProviderConfig instance
                identity = request.context.get_token(request)
                # identity is a GoogleOAuthIdentity object
                ...
    """
    ocs = {}
    for name in settings:
        if name.startswith("oauth2."):
            comps = name.split('.')
            provider = comps[1]
            attribute = comps[2]
            value = settings[name]
            if attribute == "id_class":
                value, defconf = id_classes[value]
                conf = defconf.copy()
                if provider in ocs:
                    conf.update(ocs[provider])
                ocs[provider] = conf
            if provider not in ocs:
                ocs[provider] = {}
            ocs[provider][attribute] = value

    oauth_config = OAuthConfig()
    for provider in ocs:
        provider_config = OAuthProviderConfig(provider, settings['oauth2callback'])
        for attribute, value in ocs[provider].items():
            setattr(provider_config, attribute, value)
        oauth_config.add(provider_config)

    def register_oauth_config():
        config.registry.registerUtility(oauth_config, IOAuthConfig)
    config.action('register_oauth_config', register_oauth_config)
    return oauth_config


def oauth2_config(request):
    return request.registry.getUtility(IOAuthConfig)


def includeme(config):
    settings = config.get_settings()
    oauth_config = configure_oauth2(config, settings)

    oauth2callback = urlparse(settings['oauth2callback'])
    config.add_route('oauth2callback', oauth2callback.path + '*traverse',
                     factory=lambda request: oauth_config)

# vim: ts=4 sw=4 et nu
