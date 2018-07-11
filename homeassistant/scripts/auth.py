"""Script to manage users for the Home Assistant auth provider."""
import argparse
import asyncio
import os

from homeassistant import auth
from homeassistant.auth.providers import homeassistant as hass_auth
from homeassistant.core import HomeAssistant
from homeassistant.config import get_default_config_dir


def run(args):
    """Handle Home Assistant auth provider script."""
    parser = argparse.ArgumentParser(
        description="Manage Home Assistant users")
    parser.add_argument(
        '--script', choices=['auth'])
    parser.add_argument(
        '-c', '--config',
        default=get_default_config_dir(),
        help="Directory that contains the Home Assistant configuration")

    subparsers = parser.add_subparsers(dest='func')
    subparsers.required = True
    parser_list = subparsers.add_parser('list')
    parser_list.set_defaults(func=list_users)
    parser_list.add_argument('-a', '--all', default=False,
                             help="Show all users included system user")

    parser_add = subparsers.add_parser('add')
    parser_add.add_argument('username', type=str)
    parser_add.add_argument('password', type=str)
    parser_add.set_defaults(func=add_user)

    parser_validate_login = subparsers.add_parser('validate')
    parser_validate_login.add_argument('username', type=str)
    parser_validate_login.add_argument('password', type=str)
    parser_validate_login.add_argument('--code', default=None, type=str)
    parser_validate_login.set_defaults(func=validate_login)

    parser_change_pw = subparsers.add_parser('change_password')
    parser_change_pw.add_argument('username', type=str)
    parser_change_pw.add_argument('new_password', type=str)
    parser_change_pw.set_defaults(func=change_password)

    parser_enable_mfa = subparsers.add_parser('enable_mfa')
    parser_enable_mfa.add_argument('username', type=str)
    parser_enable_mfa.add_argument('password', type=str)
    parser_enable_mfa.set_defaults(func=enable_mfa)

    args = parser.parse_args(args)
    loop = asyncio.get_event_loop()
    hass = HomeAssistant(loop=loop)
    hass.config.config_dir = os.path.join(os.getcwd(), args.config)

    provider_config = [{'type': 'homeassistant'}]
    module_config = [{'type': 'totp'}]
    hass.auth = loop.run_until_complete(
        auth.auth_manager_from_config(hass, provider_config, module_config))

    data = hass_auth.Data(hass)
    loop.run_until_complete(data.async_load())
    loop.run_until_complete(args.func(hass.auth, data, args))


async def list_users(auth_manager, data, args):
    """List the users."""
    count = 0
    if args.all:
        # pylint: disable=protected-access
        for user in await auth_manager._store.async_get_users():
            print("{}{}{}".format(
                str(user.name).ljust(20),
                str(user.id).ljust(34),
                str(user.mfa_modules)
            ))
            count += 1
            for cred in user.credentials:
                print("  - {}".format(cred.data.get('username')))

    else:
        provider = list(auth_manager.async_auth_providers)[0]
        for user in await provider.async_credentials():
            count += 1
            print(user.data.get('username'))

    print()
    print("Total users:", count)


async def add_user(auth_manager, data, args):
    """Create a user."""
    data.add_user(args.username, args.password)
    await data.async_save()
    print("User created")


async def validate_login(auth_manager, data, args):
    """Validate a login."""
    try:
        data.validate_login(args.username, args.password)
        if args.code:
            provider = list(auth_manager.async_auth_providers)[0]
            credential = await provider.async_get_or_create_credentials(
                {'username': args.username})
            user = await auth_manager.async_get_or_create_user(credential)

            module = await auth_manager.async_get_auth_module('totp')
            result = await module.async_validation_flow(
                user.id, {'code': args.code})
            if result is not None:
                print("Auth valid")
            else:
                print("Auth invalid")
        else:
            print("Auth valid")
    except (hass_auth.InvalidAuth, auth.InvalidAuth):
        print("Auth invalid")


async def change_password(auth_manager, data, args):
    """Change password."""
    try:
        data.change_password(args.username, args.new_password)
        await data.async_save()
        print("Password changed")
    except hass_auth.InvalidUser:
        print("User not found")


async def enable_mfa(auth_manager, data, args):
    """Enable mfa for user."""
    try:
        data.validate_login(args.username, args.password)

        provider = list(auth_manager.async_auth_providers)[0]
        credential = await provider.async_get_or_create_credentials(
            {'username': args.username})
        user = await auth_manager.async_get_or_create_user(credential)
        secret = await auth_manager.async_enable_user_mfa(user, 'totp')
        # FIXME need to wait until AuthStore save finish
        print(
            "Multi-factor auth enabled, please set up Google Authenticator or"
            " any other compatible apps like Authy with key: %s" % secret)
    except hass_auth.InvalidUser:
        print("User not found")
    except (hass_auth.InvalidAuth, auth.InvalidAuth):
        print("Auth invalid")
