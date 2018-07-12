"""Test the example module auth module."""
from homeassistant import auth, data_entry_flow
from homeassistant.auth.mfa_modules import _auth_module_from_config
from tests.common import MockUser


async def test_validate(hass):
    """Test validating pin."""
    auth_module = await _auth_module_from_config(hass, {
        'type': 'insecure_example',
        'users': [{'user_id': 'test-user', 'pin': '123456'}]
    })
    await auth_module.async_initialize()

    user_id = await auth_module.async_validation_flow(
            'test-user', {'pin': '123456'})
    assert user_id == 'test-user'


async def test_setup_user(hass):
    """Test setup user."""
    auth_module = await _auth_module_from_config(hass, {
        'type': 'insecure_example',
        'users': []
    })
    await auth_module.async_initialize()

    result = await auth_module.async_setup_user('test-user', pin='123456')
    assert result == '123456'

    user_id = await auth_module.async_validation_flow(
            'test-user', {'pin': '123456'})
    assert user_id == 'test-user'


async def test_depose_user(hass):
    """Test despose user."""
    auth_module = await _auth_module_from_config(hass, {
        'type': 'insecure_example',
        'users': [{'user_id': 'test-user', 'pin': '123456'}]
    })
    await auth_module.async_initialize()
    assert len(auth_module.users) == 1

    await auth_module.async_depose_user('test-user')
    assert len(auth_module.users) == 0


async def test_login(hass):
    """Test login flow with auth module."""
    hass.auth = await auth.auth_manager_from_config(hass, [{
        'type': 'insecure_example',
        'users': [{'username': 'test-user', 'password': 'test-pass'}],
    }], [{
        'type': 'insecure_example',
        'users': [{'user_id': 'mock-user', 'pin': '123456'}]
    }])
    user = MockUser(
        id='mock-user',
        is_owner=False,
        is_active=False,
        name='Paulus',
        mfa_modules=['insecure_example']
    ).add_to_auth_manager(hass.auth)
    await hass.auth.async_link_user(user, auth.Credentials(
        id='mock-id',
        auth_provider_type='insecure_example',
        auth_provider_id=None,
        data={'username': 'test-user'},
        is_new=False,
    ))

    provider = list(hass.auth.async_auth_providers)[0]
    flow = await provider.async_login_flow()

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
    assert result['data_schema'].schema.get('pin') == str

    result = await flow.async_step_mfa({'pin': 'invalid-code'})
    assert result['type'] == data_entry_flow.RESULT_TYPE_FORM
    assert result['errors']['base'] == 'invalid_auth'

    result = await flow.async_step_mfa({'pin': '123456'})
    assert result['type'] == data_entry_flow.RESULT_TYPE_CREATE_ENTRY
    assert result['data']['username'] == 'test-user'
