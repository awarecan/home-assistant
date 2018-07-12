"""Time-based One Time Password auth module."""
import logging
from collections import OrderedDict

import voluptuous as vol

from homeassistant import auth
from . import MultiFactorAuthModule, MULTI_FACTOR_AUTH_MODULES, \
    MULTI_FACTOR_AUTH_MODULE_SCHEMA

REQUIREMENTS = ['pyotp==2.2.6']

CONFIG_SCHEMA = MULTI_FACTOR_AUTH_MODULE_SCHEMA.extend({
}, extra=vol.PREVENT_EXTRA)

STORAGE_VERSION = 1
STORAGE_KEY = 'auth_module.totp'

_LOGGER = logging.getLogger(__name__)


@MULTI_FACTOR_AUTH_MODULES.register('totp')
class TotpAuthModule(MultiFactorAuthModule):
    """Auth module validate time-based one time password."""

    DEFAULT_TITLE = 'Time-based One Time Password'

    def __init__(self, hass, config):
        """Initialize the user data store."""
        super().__init__(hass, config)
        self._data = None
        self._user_store = hass.helpers.storage.Store(
            STORAGE_VERSION, STORAGE_KEY)

    @property
    def input_schema(self):
        """Input schema."""
        schema = OrderedDict()
        schema['code'] = str
        return schema

    @property
    def users(self):
        """Return users."""
        return self._data['users']

    async def async_initialize(self):
        """Initialize the auth module."""
        await self.async_load()

    async def async_load(self):
        """Load stored data."""
        data = await self._user_store.async_load()

        if data is None:
            data = {'users': []}

        if 'users' not in data:
            data['users'] = []

        self._data = data

    async def async_save(self):
        """Save data."""
        await self._user_store.async_save(self._data)

    def add_ota_secret(self, user_id):
        """Create a ota_secret for user."""
        import pyotp

        ota_secret = pyotp.random_base32()

        for user in self.users:
            if user and user.get('user_id') == user_id:
                # found user, override ota secret
                user['ota_secret'] = ota_secret
                return ota_secret

        self.users.append({
            'user_id': user_id,
            'ota_secret': ota_secret
        })
        return ota_secret

    async def async_setup_user(self, user_id, **kwargs):
        """Setup auth module for user."""
        result = await self.hass.async_add_executor_job(
            self.add_ota_secret, user_id)
        await self.async_save()
        return result

    async def async_depose_user(self, user_id):
        """Depose auth module for user."""
        found = None
        for user in self.users:
            if user and user.get('user_id') == user_id:
                found = user
                break
        if found:
            self.users.remove(found)
        await self.async_save()

    async def async_validation_flow(self, user_id, user_input):
        """Return username if validation passed."""
        if user_id is None or user_input is None:
            raise auth.InvalidAuth

        await self.hass.async_add_executor_job(
            self.validate_2fa, user_id, user_input.get('code'))
        return user_id

    def validate_2fa(self, user_id, code):
        """Validate two factor authentication code.

        Raises InvalidAuth if auth invalid.
        """
        if user_id is None:
            raise auth.InvalidAuth

        import pyotp

        ota_secret = None
        for user in self.users:
            if user_id == user.get('user_id'):
                ota_secret = user.get('ota_secret')
                break

        if ota_secret is None:
            # even we cannot find user, we still do verify
            # to make timing the same as if user was found.
            pyotp.TOTP(pyotp.random_base32()).verify(code)
            raise auth.InvalidAuth

        ota = pyotp.TOTP(ota_secret)
        if not ota.verify(code):
            raise auth.InvalidAuth
