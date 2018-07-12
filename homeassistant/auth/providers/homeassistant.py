"""Home Assistant auth provider."""
import base64
import hashlib
import hmac
import logging
from collections import OrderedDict

import voluptuous as vol

from homeassistant import auth
from homeassistant.auth import InvalidAuth, InvalidUser

from . import AUTH_PROVIDER_SCHEMA, AUTH_PROVIDERS, AuthProvider, LoginFlow

STORAGE_VERSION = 1
STORAGE_KEY = 'auth_provider.homeassistant'

CONFIG_SCHEMA = AUTH_PROVIDER_SCHEMA.extend({
}, extra=vol.PREVENT_EXTRA)


_LOGGER = logging.getLogger(__name__)


class Data:
    """Hold the user data."""

    def __init__(self, hass):
        """Initialize the user data store."""
        self.hass = hass
        self._store = hass.helpers.storage.Store(STORAGE_VERSION, STORAGE_KEY)
        self._data = None

    async def async_load(self):
        """Load stored data."""
        data = await self._store.async_load()

        if data is None:
            data = {
                'salt': auth.generate_secret(),
                'users': [],
            }

        self._data = data

    @property
    def users(self):
        """Return users."""
        return self._data['users']

    def validate_login(self, username, password):
        """Validate a username and password.

        Raises InvalidAuth if auth invalid.
        """
        password = self.hash_password(password)

        found = None

        # Compare all users to avoid timing attacks.
        for user in self.users:
            if username == user['username']:
                found = user

        if found is None:
            # Do one more compare to make timing the same as if user was found.
            hmac.compare_digest(password, password)
            raise InvalidAuth

        if not hmac.compare_digest(password,
                                   base64.b64decode(found['password'])):
            raise InvalidAuth

    def hash_password(self, password, for_storage=False):
        """Encode a password."""
        hashed = hashlib.pbkdf2_hmac(
            'sha512', password.encode(), self._data['salt'].encode(), 100000)
        if for_storage:
            hashed = base64.b64encode(hashed).decode()
        return hashed

    def add_user(self, username, password):
        """Add a user."""
        if any(user['username'] == username for user in self.users):
            raise InvalidUser

        self.users.append({
            'username': username,
            'password': self.hash_password(password, True),
        })

    def change_password(self, username, new_password):
        """Update the password of a user.

        Raises InvalidUser if user cannot be found.
        """
        for user in self.users:
            if user['username'] == username:
                user['password'] = self.hash_password(new_password, True)
                break
        else:
            raise InvalidUser

    async def async_save(self):
        """Save data."""
        await self._store.async_save(self._data)


@AUTH_PROVIDERS.register('homeassistant')
class HassAuthProvider(AuthProvider):
    """Auth provider based on a local storage of users in HASS config dir."""

    DEFAULT_TITLE = 'Home Assistant Local'

    async def async_login_flow(self):
        """Return a flow to login."""
        return HassLoginFlow(self)

    async def async_validate_login(self, username, password):
        """Helper to validate a username and password."""
        data = Data(self.hass)
        await data.async_load()
        await self.hass.async_add_executor_job(
            data.validate_login, username, password)

    async def async_get_or_create_credentials(self, flow_result):
        """Get credentials based on the flow result."""
        username = flow_result['username']

        for credential in await self.async_credentials():
            if credential.data['username'] == username:
                return credential

        # Create new credentials.
        return self.async_create_credentials({
            'username': username
        })


class HassLoginFlow(LoginFlow):
    """Handler for the login flow."""

    async def async_step_init(self, user_input=None):
        """Handle the step of username/password validation."""
        errors = {}
        result = None

        if user_input is not None:
            try:
                await self._auth_provider.async_validate_login(
                    user_input['username'], user_input['password'])
                result = user_input['username']
            except InvalidAuth:
                errors['base'] = 'invalid_auth'

            if not errors and result:
                return await self.async_finish(result)

        schema = OrderedDict()
        schema['username'] = str
        schema['password'] = str

        return self.async_show_form(
            step_id='init',
            data_schema=vol.Schema(schema),
            errors=errors,
        )
