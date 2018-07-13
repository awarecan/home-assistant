"""Test the auth script to manage local users."""
import asyncio
from unittest.mock import Mock, patch

import pytest

from homeassistant import auth
from homeassistant.auth.providers import homeassistant as hass_auth
from homeassistant.scripts import auth as script_auth
from tests.common import MockUser


@pytest.fixture
def data(hass):
    """Create a loaded data class."""
    data = hass_auth.Data(hass)
    hass.loop.run_until_complete(data.async_load())

    return data


@pytest.fixture
def auth_hass(hass):
    """Setup an auth manager."""
    manager = hass.loop.run_until_complete(
        auth.auth_manager_from_config(
            hass, [{'type': 'homeassistant'}], [{'type': 'totp'}]))
    hass.auth = manager

    # Add fake user with credentials for example auth provider.
    user = MockUser(
        id='mock-user',
        is_owner=False,
        is_active=True,
        name='Paulus',
        mfa_modules=['homeassistant']
    ).add_to_auth_manager(manager)
    user.credentials.append(auth.Credentials(
        id='mock-id',
        auth_provider_type='homeassistant',
        auth_provider_id=None,
        data={'username': 'test-user'},
        is_new=False,
    ))
    return hass


async def test_list_user(auth_hass, data, capsys):
    """Test we can list users."""
    await script_auth.list_users(auth_hass, None, Mock(all=False))

    captured = capsys.readouterr()

    assert captured.out == '\n'.join([
        'test-user',
        '',
        'Total users: 1',
        ''
    ])

    await script_auth.list_users(auth_hass, None, Mock(all=True))

    captured = capsys.readouterr()

    assert captured.out == '\n'.join([
        '{}{}{}'.format(
            'Paulus              ',
            'mock-user                         ',
            "['homeassistant']"),
        '  - test-user',
        '',
        'Total users: 1',
        ''
    ])


async def test_add_user(auth_hass, data, capsys, hass_storage):
    """Test we can add a user."""
    with patch.object(auth_hass, 'async_stop') as mock:
        future = asyncio.Future()
        future.set_result(True)
        mock.return_value = future
        await script_auth.add_user(
            auth_hass, data, Mock(username='paulus', password='test-pass'))

    assert len(hass_storage[hass_auth.STORAGE_KEY]['data']['users']) == 1

    captured = capsys.readouterr()
    assert captured.out == 'User created\n'

    assert len(data.users) == 1
    data.validate_login('paulus', 'test-pass')


async def test_validate_login(auth_hass, data, capsys):
    """Test we can validate a user login."""
    data.add_auth('test-user', 'test-pass')

    await script_auth.validate_login(
        auth_hass, data,
        Mock(username='test-user', password='test-pass', code=None))
    captured = capsys.readouterr()
    assert captured.out == 'Auth valid\n'

    await script_auth.validate_login(
        auth_hass, data,
        Mock(username='test-user', password='invalid-pass', code=None))
    captured = capsys.readouterr()
    assert captured.out == 'Auth invalid\n'

    await script_auth.validate_login(
        auth_hass, data,
        Mock(username='invalid-user', password='test-pass', code=None))
    captured = capsys.readouterr()
    assert captured.out == 'Auth invalid\n'


async def test_validate_login_2fa(auth_hass, data, capsys):
    """Test we can validate a user login."""
    data.add_auth('test-user', 'test-pass')

    with patch.object(auth_hass, 'async_stop') as mock:
        future = asyncio.Future()
        future.set_result(True)
        mock.return_value = future
        await script_auth.enable_mfa(
            auth_hass, data,
            Mock(username='test-user', password='test-pass'))
    capsys.readouterr()

    with patch('pyotp.TOTP.verify', return_value=True):
        await script_auth.validate_login(
            auth_hass, data,
            Mock(username='test-user', password='test-pass', code='code'))
        captured = capsys.readouterr()
        assert captured.out == 'Auth valid\n'

    with patch('pyotp.TOTP.verify', return_value=True):
        await script_auth.validate_login(
            auth_hass, data,
            Mock(username='test-user', password='invalid-pass', code='code'))
        captured = capsys.readouterr()
        assert captured.out == 'Auth invalid\n'

    with patch('pyotp.TOTP.verify', return_value=True):
        await script_auth.validate_login(
            auth_hass, data,
            Mock(username='invalid-user', password='test-pass', code='code'))
        captured = capsys.readouterr()
        assert captured.out == 'Auth invalid\n'

    with patch('pyotp.TOTP.verify', return_value=False):
        await script_auth.validate_login(
            auth_hass, data,
            Mock(username='test-user', password='test-pass', code='invalid'))
        captured = capsys.readouterr()
        assert captured.out == 'Auth invalid\n'


async def test_change_password(auth_hass, data, capsys, hass_storage):
    """Test we can change a password."""
    data.add_auth('test-user', 'test-pass')

    await script_auth.change_password(
        auth_hass, data,
        Mock(username='test-user', new_password='new-pass'))

    assert len(hass_storage[hass_auth.STORAGE_KEY]['data']['users']) == 1
    captured = capsys.readouterr()
    assert captured.out == 'Password changed\n'
    data.validate_login('test-user', 'new-pass')
    with pytest.raises(auth.InvalidAuth):
        data.validate_login('test-user', 'test-pass')


async def test_change_password_invalid_user(auth_hass, data,
                                            capsys, hass_storage):
    """Test changing password of non-existing user."""
    data.add_auth('test-user', 'test-pass')

    await script_auth.change_password(
        auth_hass, data,
        Mock(username='invalid-user', new_password='new-pass'))

    assert hass_auth.STORAGE_KEY not in hass_storage
    captured = capsys.readouterr()
    assert captured.out == 'User not found\n'
    data.validate_login('test-user', 'test-pass')
    with pytest.raises(auth.InvalidAuth):
        data.validate_login('invalid-user', 'new-pass')


async def test_enable_mfa(auth_hass, data, capsys):
    """Test we can change a password."""
    data.add_auth('test-user', 'test-pass')

    with patch.object(auth_hass, 'async_stop') as mock:
        future = asyncio.Future()
        future.set_result(True)
        mock.return_value = future
        await script_auth.enable_mfa(
            auth_hass, data,
            Mock(username='test-user', password='test-pass'))

    captured = capsys.readouterr()
    assert 'Multi-factor auth enabled' in captured.out


def test_parsing_args(loop):
    """Test we parse args correctly."""
    called = False

    async def mock_func(auth_hass, data, args2):
        """Mock function to be called."""
        nonlocal called
        called = True
        assert auth_hass.config.config_dir == '/somewhere/config'
        assert data.hass.config.config_dir == '/somewhere/config'
        assert args2 is args

    args = Mock(config='/somewhere/config', func=mock_func)

    with patch('argparse.ArgumentParser.parse_args', return_value=args):
        script_auth.run(None)

    assert called, 'Mock function did not get called'
