from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass

from dataclasses import asdict

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo

from . import SIGNAL_UPDATE, PeblarState
from .const import DOMAIN


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    async_add_entities(
        [
            PeblarStateSensor(hass, entry),
            PeblarPowerSensor(hass, entry),
            PeblarEnergySensor(hass, entry),
            PeblarWifiRssiSensor(hass, entry),
            PeblarLteCarrierSensor(hass, entry),
        ],
        True,
    )


class _BasePeblarSensor(SensorEntity):
    _attr_should_poll = False

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry):
        self.hass = hass
        self.entry = entry
        self._unsub = None

    @property
    def device_info(self) -> DeviceInfo:
        host = self.entry.data.get("host", "peblar")
        return DeviceInfo(
            identifiers={(DOMAIN, self.entry.entry_id)},
            name=f"Peblar Charger ({host})",
            manufacturer="Peblar (OEM Coolblue/BlueBuilt)",
            model="WLAC (WebSocket API)",
            configuration_url=f"http://{host}/",
        )

    @property
    def _state_obj(self) -> PeblarState:
        return self.hass.data[DOMAIN][self.entry.entry_id]["state"]

    async def async_added_to_hass(self):
        self._unsub = async_dispatcher_connect(
            self.hass, f"{SIGNAL_UPDATE}_{self.entry.entry_id}", self._handle_update
        )

    async def async_will_remove_from_hass(self):
        if self._unsub:
            self._unsub()
            self._unsub = None

    @callback
    def _handle_update(self):
        self.async_write_ha_state()


class PeblarStateSensor(_BasePeblarSensor):
    def __init__(self, hass, entry):
        super().__init__(hass, entry)
        self._attr_name = "Peblar State"
        self._attr_unique_id = f"{entry.entry_id}_state"
        self._attr_device_class = SensorDeviceClass.ENUM
        self._attr_icon = "mdi:ev-plug-type2"

    @property
    def native_value(self):
        return self._state_obj.session_state

    @property
    def extra_state_attributes(self):
        return asdict(self._state_obj)


class PeblarPowerSensor(_BasePeblarSensor):
    _attr_name = "Peblar Power"
    _attr_native_unit_of_measurement = "W"
    _attr_device_class = SensorDeviceClass.POWER
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:lightning-bolt"

    def __init__(self, hass, entry):
        super().__init__(hass, entry)
        self._attr_unique_id = f"{entry.entry_id}_power_w"

    @property
    def native_value(self):
        p = self._state_obj.instantaneous_power or [0, 0, 0]
        try:
            return int(sum(p))
        except Exception:
            return None


class PeblarEnergySensor(_BasePeblarSensor):
    _attr_name = "Peblar Total Energy"
    _attr_native_unit_of_measurement = "Wh"
    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_icon = "mdi:lightning-bolt"

    def __init__(self, hass, entry):
        super().__init__(hass, entry)
        self._attr_unique_id = f"{entry.entry_id}_energy_wh"

    @property
    def native_value(self):
        return self._state_obj.total_energy


class PeblarWifiRssiSensor(_BasePeblarSensor):
    _attr_name = "Peblar WiFi RSSI"
    _attr_native_unit_of_measurement = "dBm"
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:wifi"

    def __init__(self, hass, entry):
        super().__init__(hass, entry)
        self._attr_unique_id = f"{entry.entry_id}_wifi_rssi"

    @property
    def native_value(self):
        return self._state_obj.wlan_rssi


class PeblarLteCarrierSensor(_BasePeblarSensor):
    _attr_name = "Peblar LTE Carrier"
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_icon = "mdi:sim"

    def __init__(self, hass, entry):
        super().__init__(hass, entry)
        self._attr_unique_id = f"{entry.entry_id}_lte_carrier"

    @property
    def native_value(self):
        return self._state_obj.lte_carrier
