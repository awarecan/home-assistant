"""Example auth module."""
import logging
from collections import OrderedDict

import voluptuous as vol

from homeassistant import auth

CONFIG_SCHEMA = auth.AUTH_PROVIDER_SCHEMA.extend({
    vol.Required('users'): [vol.Schema({
        vol.Required('username'): str,
        vol.Required('pin'): str,
    })]
}, extra=vol.PREVENT_EXTRA)

STORAGE_VERSION = 1
STORAGE_KEY = 'auth_module.insecure_example'

_LOGGER = logging.getLogger(__name__)


@auth.AUTH_MODULES.register('insecure_example')
class InsecureExampleModule(auth.AuthModule):
    """Example auth module validate pin."""

    DEFAULT_TITLE = 'Personal Identify Number'

    def __init__(self, hass, store, config):
        """Initialize the user data store."""
        super().__init__(hass, store, config)
        self._data = None
        self._users = config.get('users')

    @property
    def input_schema(self):
        """Input schema."""
        schema = OrderedDict()
        schema['pin'] = str
        return schema

    @property
    def users(self):
        """Return users."""
        return self._users

    async def async_initialize(self):
        """Initialize the auth module."""
        pass

    async def async_create_session(self, data):
        """Create a validation session."""
        return await self.store.async_open_session(data)

    async def async_validation_flow(self, data, user_input):
        """Return username if validation passed."""
        session_data = await self.async_get_session(data)
        if session_data is None:
            raise auth.InvalidAuth

        username = session_data.get('username')
        for user in self.users:
            if username == user.get('username'):
                if user.get('pin') == user_input.get('pin'):
                    return username

        raise auth.InvalidAuth
