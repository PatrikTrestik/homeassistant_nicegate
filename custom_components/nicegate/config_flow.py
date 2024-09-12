"""Config flow for Nice gate integration."""
from __future__ import annotations

import logging
import socket
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.schema_config_entry_flow import SchemaFlowError
from homeassistant.helpers.device_registry import format_mac

from .const import DOMAIN
from .nice_api import NiceGateApi

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("host"): str,
        vol.Required("mac"): str,
        vol.Optional("username"): str,
        #vol.Optional("password"): str,
    }
)

STEP_PAIR_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("setup_code"): str,
    }
)

class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Nice gate."""

    VERSION = 1
    data: dict[str, Any]={}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        if user_input is None:
            return self.async_show_form(
                step_id="user", data_schema=STEP_USER_DATA_SCHEMA
            )
        self.data.update(user_input)
        data = await self.validate_input(self.data)
        await self.async_set_unique_id(data["device_id"])
        self._abort_if_unique_id_configured()

        return await self.async_step_pair()

    async def async_step_pair(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle pairing step."""
        if user_input is None:
            return self.async_show_form(
                step_id="pair", data_schema=STEP_PAIR_DATA_SCHEMA
            )
        self.data.update(user_input)
        user_input=await self.pair_device(self.data)

        state=await self.verify_connect(self.data)
        if state is None:
            return self.async_show_form(
                step_id="pair", data_schema=self.add_suggested_values_to_schema(STEP_PAIR_DATA_SCHEMA,self.data), errors={"base":"waiting_permission"}
            )

        return self.async_create_entry(title="Nice - gate",data=user_input)

    async def validate_input(self, data: dict[str, Any]) -> dict[str, Any]:
        """Validate the user input.
        Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
        """
        try:
            host=data.get("host")
            mac=format_mac(data.get("mac")).upper()
            ip=socket.gethostbyname(host)
            username=data.get("username")
            password = data.get("password")
            if username is None or username == "":
                username = "hass_nicegate"
        except Exception as e:
            _LOGGER.warning("Invalid host or MAC address")
            raise SchemaFlowError("invalid_host") from e

        self.data["mac"]=mac
        self.data["ip"]=ip
        self.data["username"]=username
        self.data["password"]=password
        self.data["device_id"]=mac
        return self.data

    async def pair_device(self, data: dict[str, Any]) -> dict[str, Any]:

        host=data.get("host")
        mac=data.get("mac")
        username=data.get("username")
        setup_code=data.get("setup_code")
        pwd = data.get("password")
        if pwd is not None:
            return data

        api = NiceGateApi(
            host,
            mac,
            username,
            None
        )

        pwd=await api.pair(setup_code)
        if pwd is None:
            raise InvalidAuth

        self.data["password"]=pwd
        return data

    async def verify_connect(self, data: dict[str, Any]) -> dict[str, Any]:
        host=data.get("host")
        mac=data.get("mac")
        username=data.get("username")
        pwd=data.get("password")

        api = NiceGateApi(
            host,
            mac,
            username,
            pwd
        )

        connect_state=await api.verify_connect()
        if connect_state=="connect":
            return data
        elif connect_state == "wait":
            return None
        else:
            raise CannotConnect




class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
