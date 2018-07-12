"""Example auth module."""
import logging
from collections import OrderedDict

import voluptuous as vol

from homeassistant import auth

CONFIG_SCHEMA = auth.AUTH_PROVIDER_SCHEMA.extend({
    vol.Required('users'): [vol.Schema({
        vol.Required('user_id'): str,
        vol.Required('pin'): str,
    })]
}, extra=vol.PREVENT_EXTRA)

STORAGE_VERSION = 1
STORAGE_KEY = 'auth_module.insecure_example'

_LOGGER = logging.getLogger(__name__)


@auth.MUTLFACTOR_AUTH_MODULES.register('insecure_example')
class InsecureExampleModule(auth.MultiFactorAuthModule):
    """Example auth module validate pin."""

    DEFAULT_TITLE = 'Personal Identify Number'

    def __init__(self, hass, config):
        """Initialize the user data store."""
        super().__init__(hass, config)
        self._data = None
        self._users = config.get('users', [])

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

    async def async_setup_user(self, user_id, **kwargs):
        """Setup auth module for user."""
        pin = kwargs.get('pin')
        if not pin:
            raise ValueError('Expected pin in **kwargs')
        self._users.append({'user_id': user_id, 'pin': pin})
        return pin

    async def async_validation_flow(self, user_id, user_input):
        """Return username if validation passed."""
        if user_id is None or user_input is None:
            raise auth.InvalidAuth

        for user in self.users:
            if user_id == user.get('user_id'):
                if user.get('pin') == user_input.get('pin'):
                    return user_id

        raise auth.InvalidAuth
