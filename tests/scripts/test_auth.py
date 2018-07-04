"""Test the auth script to manage local users."""
from unittest.mock import Mock, patch

import pytest

from homeassistant.scripts import auth as script_auth
from homeassistant.auth_providers import homeassistant as hass_auth
from homeassistant.auth_providers.modules import totp as hass_auth_tfa


@pytest.fixture
def enabled_2fa():
    """Control whether enable two factor auth."""
    return False


@pytest.fixture
def data(hass, enabled_2fa):
    """Create a loaded data class."""
    data = hass_auth.Data(hass)
    hass.loop.run_until_complete(data.async_load())
    if enabled_2fa:
        tfa_module = hass_auth_tfa.TotpAuthModule(
            hass, None, {'type': 'totp', 'id': 'totp'})
        hass.loop.run_until_complete(tfa_module.async_load())
        setattr(data, 'tfa_module', tfa_module)

    return data


async def test_list_user(data, capsys):
    """Test we can list users."""
    data.add_user('test-user', 'test-pass')
    data.add_user('second-user', 'second-pass')

    await script_auth.list_users(data, None)

    captured = capsys.readouterr()

    assert captured.out == '\n'.join([
        'test-user',
        'second-user',
        '',
        'Total users: 2',
        ''
    ])


async def test_add_user(data, capsys, hass_storage):
    """Test we can add a user."""
    await script_auth.add_user(
        data, Mock(username='paulus', password='test-pass', tfa=False))

    assert len(hass_storage[hass_auth.STORAGE_KEY]['data']['users']) == 1

    captured = capsys.readouterr()
    assert captured.out == 'User created\n'

    assert len(data.users) == 1
    data.validate_login('paulus', 'test-pass')


@pytest.mark.parametrize('enabled_2fa', [True])
async def test_add_user_2fa(data, capsys, hass_storage):
    """Test we can add a user wiht 2fa enabled."""
    await script_auth.add_user(
        data, Mock(username='paulus', password='test-pass', tfa=True))

    assert len(hass_storage[hass_auth.STORAGE_KEY]['data']['users']) == 1
    assert len(hass_storage[hass_auth_tfa.STORAGE_KEY]['data']['users']) == 1

    captured = capsys.readouterr()
    assert captured.out.startswith('User created, please set up Google '
                                   'Authenticator or any other compatible apps'
                                   ' like Authy with key: ')

    assert len(data.users) == 1


async def test_validate_login(data, capsys):
    """Test we can validate a user login."""
    data.add_user('test-user', 'test-pass')

    await script_auth.validate_login(
        data, Mock(username='test-user', password='test-pass', tfa=False))
    captured = capsys.readouterr()
    assert captured.out == 'Auth valid\n'

    await script_auth.validate_login(
        data, Mock(username='test-user', password='invalid-pass', tfa=False))
    captured = capsys.readouterr()
    assert captured.out == 'Auth invalid\n'

    await script_auth.validate_login(
        data, Mock(username='invalid-user', password='test-pass', tfa=False))
    captured = capsys.readouterr()
    assert captured.out == 'Auth invalid\n'


@pytest.mark.parametrize('enabled_2fa', [True])
async def test_validate_login_2fa(data, capsys):
    """Test we can validate a user login."""
    data.add_user('test-user', 'test-pass')
    data.tfa_module.add_ota_secret('test-user')

    with patch('pyotp.TOTP.verify', return_value=True):
        await script_auth.validate_login(
            data, Mock(username='test-user', password='test-pass',
                       tfa=True, code='code'))
        captured = capsys.readouterr()
        assert captured.out == 'Auth valid\n'

    with patch('pyotp.TOTP.verify', return_value=True):
        await script_auth.validate_login(
            data, Mock(username='test-user', password='invalid-pass',
                       tfa=True, code='code'))
        captured = capsys.readouterr()
        assert captured.out == 'Auth invalid\n'

    with patch('pyotp.TOTP.verify', return_value=True):
        await script_auth.validate_login(
            data, Mock(username='invalid-user', password='test-pass',
                       tfa=True, code='code'))
        captured = capsys.readouterr()
        assert captured.out == 'Auth invalid\n'

    with patch('pyotp.TOTP.verify', return_value=False):
        await script_auth.validate_login(
            data, Mock(username='test-user', password='test-pass',
                       tfa=True, code='invalid-code'))
        captured = capsys.readouterr()
        assert captured.out == 'Auth invalid\n'


async def test_change_password(data, capsys, hass_storage):
    """Test we can change a password."""
    data.add_user('test-user', 'test-pass')

    await script_auth.change_password(
        data, Mock(username='test-user', new_password='new-pass'))

    assert len(hass_storage[hass_auth.STORAGE_KEY]['data']['users']) == 1
    captured = capsys.readouterr()
    assert captured.out == 'Password changed\n'
    data.validate_login('test-user', 'new-pass')
    with pytest.raises(hass_auth.InvalidAuth):
        data.validate_login('test-user', 'test-pass')


async def test_change_password_invalid_user(data, capsys, hass_storage):
    """Test changing password of non-existing user."""
    data.add_user('test-user', 'test-pass')

    await script_auth.change_password(
        data, Mock(username='invalid-user', new_password='new-pass'))

    assert hass_auth.STORAGE_KEY not in hass_storage
    captured = capsys.readouterr()
    assert captured.out == 'User not found\n'
    data.validate_login('test-user', 'test-pass')
    with pytest.raises(hass_auth.InvalidAuth):
        data.validate_login('invalid-user', 'new-pass')


def test_parsing_args(loop):
    """Test we parse args correctly."""
    called = False

    async def mock_func(data, args2):
        """Mock function to be called."""
        nonlocal called
        called = True
        assert data.hass.config.config_dir == '/somewhere/config'
        assert args2 is args

    args = Mock(config='/somewhere/config', func=mock_func)

    with patch('argparse.ArgumentParser.parse_args', return_value=args):
        script_auth.run(None)

    assert called, 'Mock function did not get called'
