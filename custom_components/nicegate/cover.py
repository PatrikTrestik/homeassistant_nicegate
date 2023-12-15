"""Platform for Nice Gate integration."""
from __future__ import annotations

import asyncio
from datetime import timedelta
import logging
from typing import Any

import async_timeout

# Import the device class from the component that you want to support
from homeassistant.components.cover import CoverDeviceClass, CoverEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import STATE_CLOSED, STATE_CLOSING, STATE_OPEN, STATE_OPENING
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
    UpdateFailed,
)

from .const import DOMAIN
from .nice_api import NiceGateApi

_LOGGER = logging.getLogger("nicegate")

STATES_MAP = {
    "closed": STATE_CLOSED,
    "closing": STATE_CLOSING,
    "open": STATE_OPEN,
    "opening": STATE_OPENING,
    "stopped": STATE_OPEN
}


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up the Nice gate cover."""
    api = hass.data[DOMAIN][entry.entry_id]
    coordinator=NiceCoordinator(hass, api)
    await coordinator.async_config_entry_first_refresh()
    async_add_entities([NiceGate(coordinator, entry.data["mac"])])


class NiceCoordinator(DataUpdateCoordinator):
    """Nice gate custom coordinator."""

    def __init__(self, hass:HomeAssistant, api:NiceGateApi)->None:
        """Initialize."""
        super().__init__(
            hass,
            _LOGGER,
            # Name of the data. For logging purposes.
            name="Nice Gate",
            # Polling interval. Will only be polled if there are subscribers.
            update_interval=timedelta(minutes=4),
        )
        self.api = api
        self.api.set_update_callback(self.async_api_updated)

    @callback
    async def async_api_updated(self):
        self.async_set_updated_data(self.api.gate_status)

    async def async_command(self, cmd):
        await self.api.change(cmd)

    async def _async_update_data(self):
        """Fetch data from API endpoint.

        This is the place to pre-process the data to lookup tables
        so entities can quickly look up their data.
        """
        try:
            # Note: asyncio.TimeoutError and aiohttp.ClientError are already
            # handled by the data update coordinator.
            async with async_timeout.timeout(10000):
                await self.api.status()
        # except ApiAuthError as err:
        #     # Raising ConfigEntryAuthFailed will cancel future updates
        #     # and start a config flow with SOURCE_REAUTH (async_step_reauth)
        #     raise ConfigEntryAuthFailed from err
        except:
            raise UpdateFailed(f"Error communicating with API")
        return self.api.gate_status


class NiceGate(CoordinatorEntity, CoverEntity):
    """Representation of an Nice Gate."""

    _attr_device_class = CoverDeviceClass.GATE.value
    _attr_name = "Nice gate"

    def __init__(self, coordinator, device_id) -> None:
        """Initialize an NiceGate."""
        self._attr_unique_id = device_id
        self._device_id = device_id
        super().__init__(coordinator, context=device_id)
        self._state: str | None = None
        self._state_before_move: str | None = None
        self.coordinator = coordinator
        # self.api.set_update_callback(self.update_status)
        # asyncio.create_task(self.api.status())

    @property
    def is_closed(self) -> bool | None:
        """Return if the cover is closed."""
        if self._state is None:
            return None
        return self._state == STATE_CLOSED

    @property
    def is_closing(self) -> bool | None:
        """Return if the cover is closing."""
        if self._state is None:
            return None
        return self._state == STATE_CLOSING

    @property
    def is_opening(self) -> bool | None:
        """Return if the cover is opening."""
        if self._state is None:
            return None
        return self._state == STATE_OPENING

    async def async_close_cover(self, **kwargs: Any) -> None:
        """Close the cover."""
        if self._state in [STATE_CLOSED, STATE_CLOSING]:
            return
        self._state_before_move = self._state
        #self._state = STATE_CLOSING
        await self.coordinator.async_command("close")

    async def async_open_cover(self, **kwargs: Any) -> None:
        """Open the cover."""
        if self._state in [STATE_OPEN, STATE_OPENING]:
            return
        self._state_before_move = self._state
        #self._state = STATE_OPENING
        await self.coordinator.async_command("open")

    async def async_stop_cover(self, **kwargs: Any) -> None:
        """Stop the cover."""
        if self._state in [STATE_OPEN, STATE_CLOSED]:
            return
        await self.coordinator.async_command("stop")

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if self.coordinator.data is not None:
            status = self.coordinator.data
            self._state = STATES_MAP.get(status)
            self.async_write_ha_state()

