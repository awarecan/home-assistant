"""Test the example module auth module."""
from homeassistant import auth, data_entry_flow
from homeassistant.auth.providers import insecure_example as test_auth


async def test_validate(hass):
    """Test validating pin."""
    auth_module = await auth._auth_module_from_config(hass, {
        'type': 'insecure_example',
        'users': [{'username': 'test-user', 'pin': '123456'}]
    })
    await auth_module.async_initialize()

    username = await auth_module.async_validation_flow(
            'test-user', {'pin': '123456'})
    assert username == 'test-user'


async def test_login(hass):
    """Test login flow with auth module."""
    provider = test_auth.ExampleAuthProvider(hass, None, {
        'users': [{'username': 'test-user', 'password': 'test-pass'}],
        'modules': [{
            'type': 'insecure_example',
            'users': [{'username': 'test-user', 'pin': '123456'}]
        }]
    })
    await provider.async_initialize()

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
    assert result['step_id'] == 'auth_module_insecure_example'
    assert result['data_schema'].schema.get('pin') == str

    step_pin = getattr(flow, 'async_step_auth_module_insecure_example')

    result = await step_pin({'pin': 'invalid-code'})
    assert result['type'] == data_entry_flow.RESULT_TYPE_FORM
    assert result['errors']['base'] == 'invalid_auth'

    result = await step_pin({'pin': '123456'})
    assert result['type'] == data_entry_flow.RESULT_TYPE_CREATE_ENTRY
    assert result['data']['username'] == 'test-user'
