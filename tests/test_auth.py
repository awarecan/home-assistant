"""Tests for the Home Assistant auth module."""
from datetime import timedelta, datetime
from unittest.mock import Mock, patch

import pytest

from homeassistant import auth, data_entry_flow
from homeassistant.util import dt as dt_util
from tests.common import (
    MockUser, ensure_auth_manager_loaded, flush_store, CLIENT_ID)


@pytest.fixture
def mock_hass(loop):
    """Hass mock with minimum amount of data set to make it work with auth."""
    hass = Mock()
    hass.config.skip_pip = True
    return hass


async def test_auth_manager_from_config_validates_config_and_id(mock_hass):
    """Test get auth providers."""
    manager = await auth.auth_manager_from_config(mock_hass, [{
        'name': 'Test Name',
        'type': 'insecure_example',
        'users': [],
    }, {
        'name': 'Invalid config because no users',
        'type': 'insecure_example',
        'id': 'invalid_config',
    }, {
        'name': 'Test Name 2',
        'type': 'insecure_example',
        'id': 'another',
        'users': [],
    }, {
        'name': 'Wrong because duplicate ID',
        'type': 'insecure_example',
        'id': 'another',
        'users': [],
    }])

    providers = [{
            'name': provider.name,
            'id': provider.id,
            'type': provider.type,
        } for provider in manager.async_auth_providers]
    assert providers == [{
        'name': 'Test Name',
        'type': 'insecure_example',
        'id': None,
    }, {
        'name': 'Test Name 2',
        'type': 'insecure_example',
        'id': 'another',
    }]


async def test_auth_manager_from_config_auth_modules(mock_hass):
    """Test get auth modules."""
    manager = await auth.auth_manager_from_config(mock_hass, [{
        'name': 'Test Name',
        'type': 'insecure_example',
        'modules': [{
            'type': 'insecure_example',
            'users': [],
        }],
        'users': [],
    }, {
        'name': 'Duplicate modules',
        'type': 'insecure_example',
        'modules': [{
            'type': 'insecure_example',
            'users': [],
        }, {
            'type': 'insecure_example',
            'users': [],
        }],
        'id': 'duplicate',
        'users': [],
    }, {
        'name': 'Test Name 2',
        'type': 'insecure_example',
        'modules': [{
            'type': 'insecure_example',
            'id': 't1',
            'users': [],
        }, {
            'type': 'insecure_example',
            'id': 't2',
            'users': [],
        }],
        'id': 'another',
        'users': [],
    }])

    # auth module is lazy loaded
    for provider in manager.async_auth_providers:
        assert len(provider.modules) == 0
        await provider.async_initialize()

    providers = [{
            'name': provider.name,
            'type': provider.type,
            'id': provider.id,
            'modules': [{
                'id': module.id,
                'type': module.type,
            } for module in provider.modules.values()]
        } for provider in manager.async_auth_providers]
    assert providers == [{
        'name': 'Test Name',
        'type': 'insecure_example',
        'id': None,
        'modules': [{'id': None, 'type': 'insecure_example'}]
    }, {
        'name': 'Duplicate modules',
        'type': 'insecure_example',
        'id': 'duplicate',
        'modules': [{'id': None, 'type': 'insecure_example'}]
    }, {
        'name': 'Test Name 2',
        'type': 'insecure_example',
        'id': 'another',
        'modules': [{'id': 't1', 'type': 'insecure_example'},
                    {'id': 't2', 'type': 'insecure_example'}]
    }]


async def test_create_new_user(hass):
    """Test creating new user."""
    manager = await auth.auth_manager_from_config(hass, [{
        'type': 'insecure_example',
        'users': [{
            'username': 'test-user',
            'password': 'test-pass',
            'name': 'Test Name'
        }]
    }])

    step = await manager.login_flow.async_init(('insecure_example', None))
    assert step['type'] == data_entry_flow.RESULT_TYPE_FORM

    step = await manager.login_flow.async_configure(step['flow_id'], {
        'username': 'test-user',
        'password': 'test-pass',
    })
    assert step['type'] == data_entry_flow.RESULT_TYPE_CREATE_ENTRY
    credentials = step['result']
    user = await manager.async_get_or_create_user(credentials)
    assert user is not None
    assert user.is_owner is True
    assert user.name == 'Test Name'


async def test_login_as_existing_user(mock_hass):
    """Test login as existing user."""
    manager = await auth.auth_manager_from_config(mock_hass, [{
        'type': 'insecure_example',
        'users': [{
            'username': 'test-user',
            'password': 'test-pass',
            'name': 'Test Name'
        }]
    }])
    ensure_auth_manager_loaded(manager)

    # Add a fake user that we're not going to log in with
    user = MockUser(
        id='mock-user2',
        is_owner=False,
        is_active=False,
        name='Not user',
    ).add_to_auth_manager(manager)
    user.credentials.append(auth.Credentials(
        id='mock-id2',
        auth_provider_type='insecure_example',
        auth_provider_id=None,
        data={'username': 'other-user'},
        is_new=False,
    ))

    # Add fake user with credentials for example auth provider.
    user = MockUser(
        id='mock-user',
        is_owner=False,
        is_active=False,
        name='Paulus',
    ).add_to_auth_manager(manager)
    user.credentials.append(auth.Credentials(
        id='mock-id',
        auth_provider_type='insecure_example',
        auth_provider_id=None,
        data={'username': 'test-user'},
        is_new=False,
    ))

    step = await manager.login_flow.async_init(('insecure_example', None))
    assert step['type'] == data_entry_flow.RESULT_TYPE_FORM

    step = await manager.login_flow.async_configure(step['flow_id'], {
        'username': 'test-user',
        'password': 'test-pass',
    })
    assert step['type'] == data_entry_flow.RESULT_TYPE_CREATE_ENTRY
    credentials = step['result']

    user = await manager.async_get_or_create_user(credentials)
    assert user is not None
    assert user.id == 'mock-user'
    assert user.is_owner is False
    assert user.is_active is False
    assert user.name == 'Paulus'


async def test_linking_user_to_two_auth_providers(hass, hass_storage):
    """Test linking user to two auth providers."""
    manager = await auth.auth_manager_from_config(hass, [{
        'type': 'insecure_example',
        'users': [{
            'username': 'test-user',
            'password': 'test-pass',
        }]
    }, {
        'type': 'insecure_example',
        'id': 'another-provider',
        'users': [{
            'username': 'another-user',
            'password': 'another-password',
        }]
    }])

    step = await manager.login_flow.async_init(('insecure_example', None))
    step = await manager.login_flow.async_configure(step['flow_id'], {
        'username': 'test-user',
        'password': 'test-pass',
    })
    user = await manager.async_get_or_create_user(step['result'])
    assert user is not None

    step = await manager.login_flow.async_init(('insecure_example',
                                                'another-provider'))
    step = await manager.login_flow.async_configure(step['flow_id'], {
        'username': 'another-user',
        'password': 'another-password',
    })
    await manager.async_link_user(user, step['result'])
    assert len(user.credentials) == 2


async def test_saving_loading(hass, hass_storage):
    """Test storing and saving data.

    Creates one of each type that we store to test we restore correctly.
    """
    manager = await auth.auth_manager_from_config(hass, [{
        'type': 'insecure_example',
        'users': [{
            'username': 'test-user',
            'password': 'test-pass',
        }]
    }])

    step = await manager.login_flow.async_init(('insecure_example', None))
    step = await manager.login_flow.async_configure(step['flow_id'], {
        'username': 'test-user',
        'password': 'test-pass',
    })
    user = await manager.async_get_or_create_user(step['result'])

    refresh_token = await manager.async_create_refresh_token(user, CLIENT_ID)

    manager.async_create_access_token(refresh_token)

    await flush_store(manager._store._store)

    store2 = auth.AuthStore(hass)
    users = await store2.async_get_users()
    assert len(users) == 1
    assert users[0] == user


def test_access_token_expired():
    """Test that the expired property on access tokens work."""
    refresh_token = auth.RefreshToken(
        user=None,
        client_id='bla'
    )

    access_token = auth.AccessToken(
        refresh_token=refresh_token
    )

    assert access_token.expired is False

    with patch('homeassistant.auth.dt_util.utcnow',
               return_value=dt_util.utcnow() + auth.ACCESS_TOKEN_EXPIRATION):
        assert access_token.expired is True

    almost_exp = dt_util.utcnow() + auth.ACCESS_TOKEN_EXPIRATION - timedelta(1)
    with patch('homeassistant.auth.dt_util.utcnow', return_value=almost_exp):
        assert access_token.expired is False


async def test_cannot_retrieve_expired_access_token(hass):
    """Test that we cannot retrieve expired access tokens."""
    manager = await auth.auth_manager_from_config(hass, [])
    user = MockUser().add_to_auth_manager(manager)
    refresh_token = await manager.async_create_refresh_token(user, CLIENT_ID)
    assert refresh_token.user.id is user.id
    assert refresh_token.client_id == CLIENT_ID

    access_token = manager.async_create_access_token(refresh_token)
    assert manager.async_get_access_token(access_token.token) is access_token

    with patch('homeassistant.auth.dt_util.utcnow',
               return_value=dt_util.utcnow() + auth.ACCESS_TOKEN_EXPIRATION):
        assert manager.async_get_access_token(access_token.token) is None

    # Even with unpatched time, it should have been removed from manager
    assert manager.async_get_access_token(access_token.token) is None


async def test_generating_system_user(hass):
    """Test that we can add a system user."""
    manager = await auth.auth_manager_from_config(hass, [])
    user = await manager.async_create_system_user('Hass.io')
    token = await manager.async_create_refresh_token(user)
    assert user.system_generated
    assert token is not None
    assert token.client_id is None


async def test_refresh_token_requires_client_for_user(hass):
    """Test that we can add a system user."""
    manager = await auth.auth_manager_from_config(hass, [])
    user = MockUser().add_to_auth_manager(manager)
    assert user.system_generated is False

    with pytest.raises(ValueError):
        await manager.async_create_refresh_token(user)

    token = await manager.async_create_refresh_token(user, CLIENT_ID)
    assert token is not None
    assert token.client_id == CLIENT_ID


async def test_refresh_token_not_requires_client_for_system_user(hass):
    """Test that we can add a system user."""
    manager = await auth.auth_manager_from_config(hass, [])
    user = await manager.async_create_system_user('Hass.io')
    assert user.system_generated is True

    with pytest.raises(ValueError):
        await manager.async_create_refresh_token(user, CLIENT_ID)

    token = await manager.async_create_refresh_token(user)
    assert token is not None
    assert token.client_id is None


async def test_login_with_auth_module(mock_hass):
    """Test login as existing user with auth module."""
    manager = await auth.auth_manager_from_config(mock_hass, [{
        'type': 'insecure_example',
        'users': [{
            'username': 'test-user',
            'password': 'test-pass',
            'name': 'Test Name'
        }],
        'modules': [{
            'type': 'insecure_example',
            'users': [{
                'username': 'test-user',
                'pin': 'test-pin'
            }]
        }]
    }])
    ensure_auth_manager_loaded(manager)

    # Add fake user with credentials for example auth provider.
    user = MockUser(
        id='mock-user',
        is_owner=False,
        is_active=False,
        name='Paulus',
    ).add_to_auth_manager(manager)
    user.credentials.append(auth.Credentials(
        id='mock-id',
        auth_provider_type='insecure_example',
        auth_provider_id=None,
        data={'username': 'test-user'},
        is_new=False,
    ))

    step = await manager.login_flow.async_init(('insecure_example', None))
    assert step['type'] == data_entry_flow.RESULT_TYPE_FORM

    step = await manager.login_flow.async_configure(step['flow_id'], {
        'username': 'test-user',
        'password': 'test-pass',
    })

    # After auth_provider validated, request auth module input form
    assert step['type'] == data_entry_flow.RESULT_TYPE_FORM
    assert step['step_id'] == 'auth_module_insecure_example'

    step = await manager.login_flow.async_configure(step['flow_id'], {
        'pin': 'invalid-pin',
    })

    # Invalid auth error
    assert step['type'] == data_entry_flow.RESULT_TYPE_FORM
    assert step['step_id'] == 'auth_module_insecure_example'
    assert step['errors'] == {'base': 'invalid_auth'}

    step = await manager.login_flow.async_configure(step['flow_id'], {
        'pin': 'test-pin',
    })

    # Finally passed, get credentials (username)
    assert step['type'] == data_entry_flow.RESULT_TYPE_CREATE_ENTRY
    credentials = step['result']

    user = await manager.async_get_or_create_user(credentials)
    assert user is not None
    assert user.id == 'mock-user'
    assert user.is_owner is False
    assert user.is_active is False
    assert user.name == 'Paulus'


async def test_login_with_multi_auth_module(mock_hass):
    """Test login as existing user with multiple auth modules."""
    manager = await auth.auth_manager_from_config(mock_hass, [{
        'type': 'insecure_example',
        'users': [{
            'username': 'test-user',
            'password': 'test-pass',
            'name': 'Test Name'
        }],
        'modules': [{
            'type': 'insecure_example',
            'users': [{
                'username': 'test-user',
                'pin': 'test-pin'
            }]
        }, {
            'type': 'insecure_example',
            'id': 'module2',
            'users': [{
                'username': 'test-user',
                'pin': 'test-pin2'
            }]
        }]
    }])
    ensure_auth_manager_loaded(manager)

    # Add fake user with credentials for example auth provider.
    user = MockUser(
        id='mock-user',
        is_owner=False,
        is_active=False,
        name='Paulus',
    ).add_to_auth_manager(manager)
    user.credentials.append(auth.Credentials(
        id='mock-id',
        auth_provider_type='insecure_example',
        auth_provider_id=None,
        data={'username': 'test-user'},
        is_new=False,
    ))

    step = await manager.login_flow.async_init(('insecure_example', None))
    assert step['type'] == data_entry_flow.RESULT_TYPE_FORM

    step = await manager.login_flow.async_configure(step['flow_id'], {
        'username': 'test-user',
        'password': 'test-pass',
    })

    # After auth_provider validated, request first auth module input form
    assert step['type'] == data_entry_flow.RESULT_TYPE_FORM
    assert step['step_id'] == 'auth_module_insecure_example'

    step = await manager.login_flow.async_configure(step['flow_id'], {
        'pin': 'test-pin',
    })

    # Request second auth module input form, step_id included module.id
    assert step['type'] == data_entry_flow.RESULT_TYPE_FORM
    assert step['step_id'] == 'auth_module_insecure_example_module2'

    step = await manager.login_flow.async_configure(step['flow_id'], {
        'pin': 'test-pin2',
    })

    # Finally passed, get credentials (username)
    assert step['type'] == data_entry_flow.RESULT_TYPE_CREATE_ENTRY
    credentials = step['result']

    user = await manager.async_get_or_create_user(credentials)
    assert user is not None
    assert user.id == 'mock-user'
    assert user.is_owner is False
    assert user.is_active is False
    assert user.name == 'Paulus'


async def test_auth_module_expired_session(mock_hass):
    """Test login as existing user."""
    manager = await auth.auth_manager_from_config(mock_hass, [{
        'type': 'insecure_example',
        'users': [{
            'username': 'test-user',
            'password': 'test-pass',
            'name': 'Test Name'
        }],
        'modules': [{
            'type': 'insecure_example',
            'users': [{
                'username': 'test-user',
                'pin': 'test-pin'
            }]
        }]
    }])
    ensure_auth_manager_loaded(manager)

    step = await manager.login_flow.async_init(('insecure_example', None))
    assert step['type'] == data_entry_flow.RESULT_TYPE_FORM

    step = await manager.login_flow.async_configure(step['flow_id'], {
        'username': 'test-user',
        'password': 'test-pass',
    })

    assert step['type'] == data_entry_flow.RESULT_TYPE_FORM
    assert step['step_id'] == 'auth_module_insecure_example'

    with patch('homeassistant.util.dt.utcnow') as mock_now:
        mock_now.return_value = datetime.now(dt_util.UTC)\
                                + auth.SESSION_EXPIRATION * 2
        step = await manager.login_flow.async_configure(step['flow_id'], {
            'pin': 'test-pin',
        })
        # Invalid auth due session timeout
        assert step['type'] == data_entry_flow.RESULT_TYPE_FORM
        assert step['step_id'] == 'auth_module_insecure_example'
        assert step['errors']['base'] == 'invalid_auth'
