from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import HomeAssistant

from .const import DOMAIN, CONF_HOST, CONF_USERNAME, CONF_PASSWORD, CONF_USE_WS


class PeblarWSConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors = {}

        if user_input is not None:
            # Basic sanity checks only; we’ll actually validate after setup.
            host = user_input[CONF_HOST].strip()
            if host.startswith("http://") or host.startswith("https://"):
                errors["base"] = "host_format"
            else:
                return self.async_create_entry(
                    title=f"Peblar WS {host}",
                    data=user_input,
                )

        schema = vol.Schema(
            {
                vol.Required(CONF_HOST): str,
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Optional(CONF_USE_WS, default=True): bool,
            }
        )

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "host_hint": "Use IP or hostname only, e.g. 192.168.1.***"
            },
        )

    @staticmethod
    def async_get_options_flow(config_entry):
        return PeblarWSOptionsFlow(config_entry)


class PeblarWSOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, config_entry):
        self._config_entry = config_entry

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        use_ws_default = self._config_entry.options.get(
            CONF_USE_WS, self._config_entry.data.get(CONF_USE_WS, True)
        )
        schema = vol.Schema(
            {
                vol.Optional(CONF_USE_WS, default=use_ws_default): bool,
            }
        )

        return self.async_show_form(step_id="init", data_schema=schema)
