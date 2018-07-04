"""Test the Time-based One Time Password (2FA) auth module."""
from unittest.mock import patch

import pytest

from homeassistant import auth, data_entry_flow
from homeassistant.auth_providers import insecure_example as test_auth

MOCK_CODE = '123456'


async def test_validating_2fa(hass):
    """Test validating 2fa code."""
    totp_auth_module = await auth._auth_module_from_config(hass, None, {
        'type': 'totp'
    })
    await totp_auth_module.async_initialize()
    totp_auth_module.add_ota_secret('test-user')

    session = await totp_auth_module.async_create_session({
        'username': 'test-user'
    })

    with patch('pyotp.TOTP.verify', return_value=True):
        username = await totp_auth_module.async_validation_flow(
            session, {'code': MOCK_CODE})
        assert username == 'test-user'


async def test_validating_2fa_invalid_code(hass):
    """Test validating an invalid 2fa code."""
    totp_auth_module = await auth._auth_module_from_config(hass, None, {
        'type': 'totp'
    })
    await totp_auth_module.async_initialize()
    totp_auth_module.add_ota_secret('test-user')

    session = await totp_auth_module.async_create_session({
        'username': 'test-user'
    })

    with patch('pyotp.TOTP.verify', return_value=False):
        with pytest.raises(auth.InvalidAuth):
            await totp_auth_module.async_validation_flow(
                session, {'code': MOCK_CODE})


async def test_validating_2fa_invalid_session(hass):
    """Test validating an 2fa code with invalid session_token."""
    totp_auth_module = await auth._auth_module_from_config(hass, None, {
        'type': 'totp'
    })
    await totp_auth_module.async_initialize()
    totp_auth_module.add_ota_secret('test-user')

    with pytest.raises(auth.InvalidAuth):
        await totp_auth_module.async_validation_flow(
            'invalid-session', {'code': MOCK_CODE})


async def test_login_flow_validates_2fa(hass):
    """Test login flow with 2fa enabled."""
    provider = test_auth.ExampleAuthProvider(hass, None, {
        'users': [{'username': 'test-user', 'password': 'test-pass'}],
        'modules': [{'type': 'totp'}]
    })

    # Load module
    await provider.async_initialize()
    assert len(provider.modules) == 1
    totp_auth_module = list(provider.modules.values())[0]
    await totp_auth_module.async_initialize()
    totp_auth_module.add_ota_secret('test-user')

    flow = test_auth.LoginFlow(provider)
    result = await flow.async_step_init()
    assert result['type'] == data_entry_flow.RESULT_TYPE_FORM

    result = await flow.async_step_init({
        'username': 'incorrect-user',
        'password': 'test-pass',
    })
    assert result['type'] == data_entry_flow.RESULT_TYPE_FORM
    assert result['errors']['base'] == 'invalid_auth'

    result = await flow.async_step_init({
        'username': 'test-user',
        'password': 'incorrect-pass',
    })
    assert result['type'] == data_entry_flow.RESULT_TYPE_FORM
    assert result['errors']['base'] == 'invalid_auth'

    result = await flow.async_step_init({
        'username': 'test-user',
        'password': 'test-pass',
    })
    assert result['type'] == data_entry_flow.RESULT_TYPE_FORM
    assert result['step_id'] == 'auth_module_totp'
    assert result['data_schema'].schema.get('code') == str

    step_2fa = getattr(flow, 'async_step_auth_module_totp')

    with patch('pyotp.TOTP.verify', return_value=False):
        result = await step_2fa({'code': 'invalid-code'})
        assert result['type'] == data_entry_flow.RESULT_TYPE_FORM
        assert result['errors']['base'] == 'invalid_auth'

    with patch('pyotp.TOTP.verify', return_value=True):
        result = await step_2fa({'code': MOCK_CODE})
        assert result['type'] == data_entry_flow.RESULT_TYPE_CREATE_ENTRY
        assert result['data']['username'] == 'test-user'
