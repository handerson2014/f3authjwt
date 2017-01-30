"""Helpers."""
import json
import logging
import base64
import ferris3 as f3
from ferris3.caching import cache
from authentication_types import BasiAuthentication
CONFIG_FILE_PATH = 'auth_jwt_settings.json'


def get_payload_from_token(token):
    """get_payload_from_token."""
    # JWT is in three parts, header, token, and signature
    # separated by '.'.
    try:
        token_parts = token.split('.')
        encoded_token = token_parts[1]

        # Base64 strings should have a length divisible by 4.
        # If this one doesn't, add the '=' padding to fix it.
        leftovers = len(encoded_token) % 4
        if leftovers == 2:
            encoded_token += '=='
        elif leftovers == 3:
            encoded_token += '='

        # URL-safe base64 decode the token parts.
        decoded = base64.urlsafe_b64decode(
            encoded_token.encode('utf-8')).decode('utf-8')

        # Load decoded token into a JSON object.
        jwt = json.loads(decoded)

        return jwt
    except Exception:
        raise f3.BadRequestException('Invalid jwt token')


@cache('jwt_configuration_file', ttl=3600)
def get_configuration():
    """Get configuration from configuration file."""
    try:
        with open(CONFIG_FILE_PATH) as data_file:
            settings = json.load(data_file)
            data_file.close()
            return settings
    except Exception:
        raise f3.InternalServerErrorException("jwt config file not found")


def verify_header(headers, settings):
    """Verify if authorization header is valid."""
    authorization = headers.get('Authorization')

    if authorization:
        splited_token = authorization.split(' ')
        if len(splited_token) == 2:
            kind = splited_token[0]
            token = splited_token[1]
            kind_valid = settings.get(kind)
            if kind_valid:
                return kind, token
            else:
                logging.warning('Unsupported kind of authentication')
                raise f3.ForbiddenException('Unauthorized')
        else:
            logging.warning('Invalid Authorization header')
            raise f3.ForbiddenException('Invalid header')
    else:
        logging.warning('Authorization header was not found')
        raise f3.ForbiddenException('Unauthorized')


def execute_basic_authentication(kind, token, settings):
    """Execute basic authentication process."""
    basic_settings = settings.get('Basic')
    user = basic_settings.get("User")
    password = basic_settings.get("Password")
    basic_auth = BasiAuthentication(user, password)

    if basic_auth.verify(token):
        return True
    else:
        return False


def execute_bearer_authentication(self, kind, token, settings, client_model):
    """Execute bearer jwt authentication process."""
    bearer_settings = settings.get("Bearer")


