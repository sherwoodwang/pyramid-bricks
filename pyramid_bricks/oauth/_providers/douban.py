from .._core import OAuthIdentity


class DoubanOAuthIdentity(OAuthIdentity):
    name = 'douban'
    config = {
            'authentication_endpoint': 'https://www.douban.com/service/auth2/auth',
            'token_endpoint': 'https://www.douban.com/service/auth2/token'
            }

    douban_error_code = {
            100: 'invalid_request_scheme',
            101: 'invalid_request_method',
            102: 'access_token_is_missing',
            103: 'invalid_access_token',
            104: 'invalid_api_key',
            105: 'api_key_is_blocked',
            106: 'access_token_has_expired',
            107: 'invalid_request_uri',
            108: 'invalid_credential1',
            109: 'invalid_credential2',
            110: 'not_trial_user',
            111: 'rate_limit_exceeded1',
            112: 'rate_limit_exceeded2',
            113: 'required_parameter_is_missing',
            114: 'unsupported_grant_type',
            115: 'unsupported_response_type',
            116: 'client_secret_mismatch',
            117: 'redirect_uri_mismatch',
            118: 'invalid_authorization_code',
            119: 'invalid_refresh_token',
            120: 'username_password_mismatch',
            121: 'invalid_user',
            122: 'user_has_blocked',
            123: 'access_token_has_expired_since_password_changed',
            124: 'access_token_has_not_expired',
            125: 'invalid_request_scope',
            126: 'invalid_request_source',
            127: 'third_party_login_auth_failed',
            128: 'user_locked',
            999: 'unknown',
            }

    def __init__(self, config, status_code, data):
        if status_code == 400:
            data['error'] = self.douban_error_code[data['code']]
            data["error_description"] = data['msg']
        super().__init__(config, status_code, data)
        self.subject = self.data['douban_user_id']

DoubanOAuthIdentity.register()

# vim: ts=4 sw=4 et nu
