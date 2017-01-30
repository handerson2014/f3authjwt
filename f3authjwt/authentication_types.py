"""Define authentication types."""
import base64
import jwt
import logging


class BasiAuthentication:
    """Defin kind of authentications process."""

    def __init__(self, user, password):
        """Initializer."""
        self.user = user
        self.password = password

    def verify(self, token):
        """Execute auth."""
        decoded = base64.b64decode(token)
        values = decoded.split(":")
        if len(values) == 2:
            user = values[0]
            password = values[1]

            if self.user == user and self.password == password:
                return True
            else:
                return False
        else:
            return False


class JWTAuthentication:
    """Defind jwt authentication."""

    verify_expiration = False
    verify_signature = True
    algorithms = ['HS256']

    def __init__(self, verify_expiration, verify_signature):
        """Init."""
        self.verify_signature = verify_signature
        self.verify_expiration = verify_expiration

    def verify(self, token, signature=None):
        """Decode jwt token."""
        decoded_token = None

        options = {
            'verify_signature': self.verify_signature,
            'verify_exp': self.verify_expiration
        }

        try:
            if self.verify_signature:
                decoded_token = jwt.decode(
                    token, signature,
                    options=options,
                    algorithms=self.algorithms
                )
            else:
                decoded_token = jwt.decode(
                    token, options=options,
                    algorithms=self.algorithms
                )
            return decoded_token

        except jwt.exceptions.ExpiredSignatureError, e:
            msg = "Error: %s - %s" % (e.__class__, e.message)
            logging.warning(msg)
            return None
        except jwt.InvalidTokenError, e:
            logging.warning("Error in JWT token: %s" % e)
            return None
