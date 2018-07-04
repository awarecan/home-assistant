"""Example auth provider."""
import hmac
from collections import OrderedDict

import voluptuous as vol

from homeassistant import auth
from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError

USER_SCHEMA = vol.Schema({
    vol.Required('username'): str,
    vol.Required('password'): str,
    vol.Optional('name'): str,
})


CONFIG_SCHEMA = auth.AUTH_PROVIDER_SCHEMA.extend({
    vol.Required('users'): [USER_SCHEMA]
}, extra=vol.PREVENT_EXTRA)


class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""


@auth.AUTH_PROVIDERS.register('insecure_example')
class ExampleAuthProvider(auth.AuthProvider):
    """Example auth provider based on hardcoded usernames and passwords."""

    async def async_login_flow(self):
        """Return a flow to login."""
        return LoginFlow(self)

    @callback
    def async_validate_login(self, username, password):
        """Helper to validate a username and password."""
        user = None

        # Compare all users to avoid timing attacks.
        for usr in self.config['users']:
            if hmac.compare_digest(username.encode('utf-8'),
                                   usr['username'].encode('utf-8')):
                user = usr

        if user is None:
            # Do one more compare to make timing the same as if user was found.
            hmac.compare_digest(password.encode('utf-8'),
                                password.encode('utf-8'))
            raise InvalidAuthError

        if not hmac.compare_digest(user['password'].encode('utf-8'),
                                   password.encode('utf-8')):
            raise InvalidAuthError

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

    async def async_user_meta_for_credentials(self, credentials):
        """Return extra user metadata for credentials.

        Will be used to populate info when creating a new user.
        """
        username = credentials.data['username']

        for user in self.config['users']:
            if user['username'] == username:
                return {
                    'name': user.get('name')
                }

        return {}


class LoginFlow(auth.LoginFlow):
    """Handler for the login flow."""

    async def async_step_init(self, user_input=None):
        """Handle the step of the form."""
        errors = {}

        if user_input is not None:
            try:
                self._auth_provider.async_validate_login(
                    user_input['username'], user_input['password'])
            except InvalidAuthError:
                errors['base'] = 'invalid_auth'

            if not errors:
                return await self.async_finish(user_input['username'])

        schema = OrderedDict()
        schema['username'] = str
        schema['password'] = str

        return self.async_show_form(
            step_id='init',
            data_schema=vol.Schema(schema),
            errors=errors,
        )
