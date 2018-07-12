"""Test the Time-based One Time Password (MFA) auth module."""
from unittest.mock import patch

import pytest

from homeassistant import auth, data_entry_flow
from homeassistant.auth.providers import insecure_example as test_auth
from tests.common import MockUser

MOCK_CODE = '123456'


async def test_validating_mfa(hass):
    """Test validating mfa code."""
    totp_auth_module = await auth._auth_module_from_config(hass, {
        'type': 'totp'
    })
    await totp_auth_module.async_initialize()
    await totp_auth_module.async_setup_user('test-user')

    with patch('pyotp.TOTP.verify', return_value=True):
        user_id = await totp_auth_module.async_validation_flow(
            'test-user', {'code': MOCK_CODE})
        assert user_id == 'test-user'


async def test_validating_mfa_invalid_code(hass):
    """Test validating an invalid mfa code."""
    totp_auth_module = await auth._auth_module_from_config(hass, {
        'type': 'totp'
    })
    await totp_auth_module.async_initialize()
    await totp_auth_module.async_setup_user('test-user')

    with patch('pyotp.TOTP.verify', return_value=False):
        with pytest.raises(auth.InvalidAuth):
            await totp_auth_module.async_validation_flow(
                'test-user', {'code': MOCK_CODE})


async def test_validating_mfa_invalid_user(hass):
    """Test validating an mfa code with invalid user."""
    totp_auth_module = await auth._auth_module_from_config(hass, {
        'type': 'totp'
    })
    await totp_auth_module.async_initialize()
    await totp_auth_module.async_setup_user('test-user')

    with pytest.raises(auth.InvalidAuth):
        await totp_auth_module.async_validation_flow(
            'invalid-user', {'code': MOCK_CODE})


async def test_login_flow_validates_mfa(hass):
    """Test login flow with mfa enabled."""
    hass.auth = await auth.auth_manager_from_config(hass, [{
        'type': 'insecure_example',
        'users': [{'username': 'test-user', 'password': 'test-pass'}],
    }], [{
        'type': 'totp',
    }])
    user = MockUser(
        id='mock-user',
        is_owner=False,
        is_active=False,
        name='Paulus',
        mfa_modules=[]
    ).add_to_auth_manager(hass.auth)
    await hass.auth.async_link_user(user, auth.Credentials(
        id='mock-id',
        auth_provider_type='insecure_example',
        auth_provider_id=None,
        data={'username': 'test-user'},
        is_new=False,
    ))

    await hass.auth.async_enable_user_mfa(user, 'totp')

    flow = test_auth.LoginFlow(
        list(hass.auth.async_auth_providers)[0])

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
    assert result['step_id'] == 'mfa'
    assert result['data_schema'].schema.get('code') == str

    with patch('pyotp.TOTP.verify', return_value=False):
        result = await flow.async_step_mfa({'code': 'invalid-code'})
        assert result['type'] == data_entry_flow.RESULT_TYPE_FORM
        assert result['step_id'] == 'mfa'
        assert result['errors']['base'] == 'invalid_auth'

    with patch('pyotp.TOTP.verify', return_value=True):
        result = await flow.async_step_mfa({'code': MOCK_CODE})
        assert result['type'] == data_entry_flow.RESULT_TYPE_CREATE_ENTRY
        assert result['data']['username'] == 'test-user'
