"""
Support for monitoring local systemd services status.

For more details about this platform, please refer to the documentation at
https://home-assistant.io/components/binary_sensor.systemd/
For more details about D-Bus API for systemd, please refer to
https://www.freedesktop.org/wiki/Software/systemd/dbus/
"""
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Any

from homeassistant.components.binary_sensor import BinarySensorDevice
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, \
    EVENT_HOMEASSISTANT_START
from homeassistant.core import callback

REQUIREMENTS = ['pydbus==0.6.0']

_LOGGER = logging.getLogger(__name__)

CONF_UNITS = 'units'

# Incomplete list of states
STATE_LOAD_LOADED = 'loaded'
STATE_LOAD_NOT_FOUND = 'not-found'
STATE_ACTIVE_ACTIVE = 'active'
STATE_ACTIVE_INACTIVE = 'inactive'
STATE_SUB_DEAD = 'dead'
STATE_SUB_EXITED = 'exited'
STATE_SUB_PLUGGED = 'plugged'
STATE_SUB_RUNNING = 'running'

TYPE_SERVICE = 'service'
TYPE_SOCKET = 'socket'
TYPE_DEVICE = 'device'
TYPE_MOUNT = 'mount'
TYPE_AUTOMOUNT = 'automount'
TYPE_SWAP = 'swap'
TYPE_TARGET = 'target'
TYPE_PATH = 'path'
TYPE_TIMER = 'timer'
TYPE_SNAPSHOT = 'snapshot'
TYPE_SLICE = 'slice'
TYPE_SCOPE = 'scope'

BUS_NAME_SYSTEMD = "org.freedesktop.systemd1"
INTERFACE_DBUS_PROPERTIES = "org.freedesktop.DBus.Properties"
INTERFACE_SYSTEMD_MANAGER = "org.freedesktop.systemd1.Manager"
INTERFACE_SYSTEMD_UNIT = "org.freedesktop.systemd1.Unit"

PROP_LOAD_STATE = "LoadState"
PROP_ACTIVE_STATE = "ActiveState"
PROP_SUB_STATE = "SubState"

UNIT_NAME = 0
UNIT_DESCRIPTION = 1
UNIT_LOAD = 2
UNIT_ACTIVE = 3
UNIT_SUB = 4
UNIT_FOLLOWING = 5
UNIT_OBJECT_PATH = 6
UNIT_JOB_ID = 7
UNIT_JOB_TYPE = 8
UNIT_JOB_PATH = 9


@callback
def _async_add_job(hass, target: Callable[..., Any], *args: Any):
    """
    Custom async_add_job for dbus proxy method.

    hass.async_add_job will thrown exception on proxy method, due cpython issue
    https://bugs.python.org/issue33261
    """
    task = hass.loop.run_in_executor(None, target, *args)

    # If a task is scheduled
    # pylint: disable=protected-access
    if hass._track_task and task is not None:
        # pylint: disable=protected-access
        hass._pending_tasks.append(task)

    return task


async def async_setup_platform(hass, config,
                               async_add_devices, discovery_info=None):
    """Set up systemd platform."""
    from gi.repository import GLib
    from pydbus import SystemBus

    bus = await hass.async_add_job(SystemBus)
    systemd = await hass.async_add_job(bus.get, BUS_NAME_SYSTEMD)
    manager = systemd[INTERFACE_SYSTEMD_MANAGER]

    all_units = await _async_add_job(hass, manager.ListUnits)

    units = []
    for config_unit in config.get(CONF_UNITS, []):
        _LOGGER.debug("load config unit %s", config_unit)
        found = False
        for unit in all_units:
            if config_unit == unit[UNIT_NAME]:
                _LOGGER.debug("found unit %s", unit)
                obj = await hass.async_add_job(bus.get,
                                               BUS_NAME_SYSTEMD,
                                               unit[UNIT_OBJECT_PATH])
                units.append(SystemdSensor(obj, unit))
                found = True
                break
        if not found:
            _LOGGER.warning("Cannot find %s in systemd configuration.",
                            config_unit)

    async_add_devices(units, True)

    loop = GLib.MainLoop()

    @callback
    def async_start_up(event):
        """Start Glib main loop in a separate thread pool."""
        _LOGGER.debug("Start Glib main loop in a separate thread pool.")
        executor = ThreadPoolExecutor(max_workers=1)

        def run_loop():
            """Run GLib MainLoop."""
            try:
                loop.run()
            except KeyboardInterrupt:
                _LOGGER.info("GLib main loop intercepted an "
                             "KeyboardInterrupt. Notify hass to stop.")
                hass.stop()

        hass.loop.run_in_executor(executor, run_loop)

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_START, async_start_up)

    def shut_down(event):
        """Stop Glib main loop."""
        _LOGGER.debug("Stop Glib main loop in shut_down.")
        loop.quit()

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, shut_down)


class SystemdSensor(BinarySensorDevice):
    """Represent one systemd unit."""

    def __init__(self, obj, unit):
        """
        Create systemd sensor for one systemed unit.

        :param obj: a proxy object for systemed unit
        :param unit: (string, string, string, string, string, string,
                      object_path, uint32, string, object_path)
                     a tuple retrieved by ListUnits,
        """
        self._object = obj
        self._name = "{}".format(unit[UNIT_NAME])
        self._id = unit[UNIT_OBJECT_PATH]
        self._type = unit[UNIT_NAME].split('.')[-1]
        self._load_state = unit[UNIT_LOAD]
        self._active_state = unit[UNIT_ACTIVE]
        self._sub_state = unit[UNIT_SUB]
        self._properties_changed_handler = None

    async def async_added_to_hass(self):
        """Subscribe properties changed signal when added to hass."""
        _LOGGER.debug("Subscribe")

        def on_properties_changed(interface, changed_properties,
                                  invalidated_properties):
            """Handle properties changed signal, update entity state."""
            if interface == INTERFACE_SYSTEMD_UNIT:
                changed = False
                if PROP_LOAD_STATE in changed_properties:
                    self._load_state = changed_properties[PROP_LOAD_STATE]
                    changed = True
                if PROP_ACTIVE_STATE in changed_properties:
                    self._active_state = changed_properties[PROP_ACTIVE_STATE]
                    changed = True
                if PROP_SUB_STATE in changed_properties:
                    self._sub_state = changed_properties[PROP_SUB_STATE]
                    changed = True
                if changed:
                    self.async_schedule_update_ha_state()

        self._properties_changed_handler = await _async_add_job(
            self.hass, self._object.PropertiesChanged.connect,
            on_properties_changed)

        async def async_shut_down(event):
            """Unsubscribe properties changed signal."""
            await self.async_will_remove_from_hass()

        self.hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP,
                                        async_shut_down)

    async def async_will_remove_from_hass(self):
        """Unsubscribe properties changed signal when removing from hass."""
        _LOGGER.debug("Unsubscribe")
        if self._properties_changed_handler:
            await _async_add_job(self.hass,
                                 self._properties_changed_handler.disconnect)

    @property
    def should_poll(self):
        """Listening DBus Message."""
        return False

    @property
    def unique_id(self):
        """Return a unique ID."""
        return self._id

    @property
    def name(self):
        """Return the name of the sensor."""
        return self._name

    @property
    def device_class(self):
        """Return the device class of the binary sensor."""
        return self._type

    @property
    def icon(self):
        """Icon to use in the frontend, if any."""
        return 'mdi:memory'

    @property
    def is_on(self):
        """Return whether the unit is active."""
        return self._active_state == STATE_ACTIVE_ACTIVE

    @property
    def device_state_attributes(self):
        """Return more detail state."""
        return {
            'load_state': self._load_state,
            'active_state': self._active_state,
            'sub_state': self._sub_state
        }

    @callback
    def _async_get_unit_property(self, prop):
        """Get one property of interface."""
        return _async_add_job(self.hass, self._object.Get,
                              INTERFACE_SYSTEMD_UNIT, prop)

    async def async_update(self):
        """Refresh systemd unit states."""
        self._load_state = await self._async_get_unit_property(PROP_LOAD_STATE)
        self._active_state = await self._async_get_unit_property(
            PROP_ACTIVE_STATE)
        self._sub_state = await self._async_get_unit_property(PROP_SUB_STATE)
        _LOGGER.debug("%s: %s", self.name, self.state)
