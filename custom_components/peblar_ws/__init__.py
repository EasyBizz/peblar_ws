from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from datetime import timedelta
from dataclasses import dataclass
from typing import Any

from aiohttp import ClientSession, WSMsgType
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import (
    DOMAIN,
    CONF_HOST,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_USE_WS,
    WS_PATH,
    LOGIN_PATH,
    TOPIC_SESSION,
    TOPIC_NETWORK,
)

_LOGGER = logging.getLogger(__name__)

SIGNAL_UPDATE = f"{DOMAIN}_update"

# Some firmwares publish live charging/meter updates on separate topics.
# Subscribing to a few "known common" ones is harmless (you'll just receive nothing for unknown topics).
EXTRA_TOPICS = [
    "/meter/status",
    "/meter/data",
    "/system/diagnostics/statuschanged",
    "/statistics/session",
]

SUBSCRIBE_TOPICS = [TOPIC_SESSION, TOPIC_NETWORK, *EXTRA_TOPICS]

POLL_INTERVAL_CHARGING = timedelta(seconds=30)
POLL_INTERVAL_IDLE = timedelta(minutes=5)
WS_RECONNECT_INTERVAL = timedelta(minutes=5)
POLL_ENDPOINTS = [
    "/api/v1/session/status",
    "/api/v1/meter/status",
    "/api/v1/meter/data",
    "/api/v1/statistics/session",
]


@dataclass
class PeblarState:
    session_state: str | None = None
    instantaneous_power: list[int] | None = None
    total_energy: int | None = None

    wlan_rssi: int | None = None
    lte_carrier: str | None = None
    lte_technology: str | None = None


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    state = PeblarState()

    use_ws = entry.options.get(CONF_USE_WS, entry.data.get(CONF_USE_WS, True))
    ws_task = None
    if use_ws:
        ws_task = hass.async_create_background_task(
            _runner(hass, entry),
            name=f"Peblar WS runner ({entry.entry_id})",
        )
    poll_task = hass.async_create_background_task(
        _poll_runner(hass, entry),
        name=f"Peblar poll runner ({entry.entry_id})",
    )

    hass.data[DOMAIN][entry.entry_id] = {
        "state": state,
        "task": ws_task,
        "poll_task": poll_task,
        "cookie": None,
    }
    entry.async_on_unload(entry.add_update_listener(_update_listener))

    await hass.config_entries.async_forward_entry_setups(entry, ["sensor"])
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = hass.data[DOMAIN].pop(entry.entry_id, None)
    if data:
        for task in (data.get("task"), data.get("poll_task")):
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    return await hass.config_entries.async_unload_platforms(entry, ["sensor"])


async def _update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def _login_and_get_cookie(
    session: ClientSession, base_url: str, username: str, password: str
) -> str:
    url = f"{base_url}{LOGIN_PATH}"

    # Try multiple common payload formats (OEM firmware often differs)
    payload_candidates = [
        {"username": username, "password": password},
        {"user": username, "pass": password},
        {"login": username, "password": password},
        {"email": username, "password": password},
        {"Username": username, "Password": password},
        {"UserName": username, "Password": password},
        {"User": username, "Password": password},
        {"name": username, "password": password},
    ]

    req_headers = {
        "Origin": base_url,
        "Referer": f"{base_url}/",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
    }

    last_error: str | None = None

    for payload in payload_candidates:
        async with session.post(url, json=payload, headers=req_headers) as resp:
            if resp.status in (200, 204):
                # Expected: 204 + Set-Cookie: sessionid=...;path=/;SameSite=Strict
                set_cookie_all = []
                try:
                    set_cookie_all = resp.headers.getall("Set-Cookie", [])
                except Exception:
                    set_cookie_all = []

                if isinstance(set_cookie_all, str):
                    set_cookie_all = [set_cookie_all]

                for sc in set_cookie_all:
                    if sc.lower().startswith("sessionid="):
                        return sc.split(";", 1)[0].strip()

                sc = resp.headers.get("Set-Cookie")
                if sc and "sessionid=" in sc.lower():
                    return sc.split(";", 1)[0].strip()

                raise RuntimeError("Login succeeded but no sessionid cookie found")

            try:
                body = await resp.text()
            except Exception:
                body = ""
            last_error = f'HTTP {resp.status}: {body[:200]} (payload keys: {list(payload.keys())})'

    raise RuntimeError(f"Login failed for all payload formats. Last error: {last_error}")


async def _runner(hass: HomeAssistant, entry: ConfigEntry) -> None:
    host = entry.data[CONF_HOST]
    username = entry.data[CONF_USERNAME]
    password = entry.data[CONF_PASSWORD]

    base_http = f"http://{host}"
    ws_url = f"ws://{host}{WS_PATH}"

    session = async_get_clientsession(hass)

    while True:
        try:
            cookie = await _login_and_get_cookie(session, base_http, username, password)
            hass.data[DOMAIN][entry.entry_id]["cookie"] = cookie
            _LOGGER.info("Peblar WS logged in; got session cookie.")

            headers = {
                "Origin": base_http,
                "Cookie": cookie,  # e.g. "sessionid=...."
            }

            async with session.ws_connect(ws_url, headers=headers, heartbeat=30) as ws:
                # Subscribe to topics (avoid guessing which one carries live meter updates)
                for topic in SUBSCRIBE_TOPICS:
                    await ws.send_str(json.dumps({"action": "subscribe", "topic": topic}))

                # Receive loop - include timeout to recover from silent stalls
                while True:
                    msg = await ws.receive(timeout=65)

                    if msg.type == WSMsgType.TEXT:
                        _handle_ws_text(hass, entry, msg.data)
                    elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSED):
                        raise RuntimeError("WebSocket closed by server")
                    elif msg.type == WSMsgType.ERROR:
                        raise RuntimeError(f"WebSocket error: {ws.exception()}")
                    elif msg.type == WSMsgType.PING:
                        # aiohttp handles ping/pong internally with heartbeat, but keep for completeness
                        continue
                    elif msg.type == WSMsgType.PONG:
                        continue
                    elif msg.type == WSMsgType.CLOSING:
                        raise RuntimeError("WebSocket closing")
                    else:
                        # ignore binary/unknown
                        continue

        except asyncio.TimeoutError:
            _LOGGER.warning("Peblar WS receive timeout; reconnecting")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            _LOGGER.warning("Peblar WS reconnecting after error: %s", e)

        await asyncio.sleep(WS_RECONNECT_INTERVAL.total_seconds())


def _update_and_notify(hass: HomeAssistant, entry: ConfigEntry, changed: bool) -> None:
    if changed:
        async_dispatcher_send(hass, f"{SIGNAL_UPDATE}_{entry.entry_id}")


def _handle_ws_text(hass: HomeAssistant, entry: ConfigEntry, text: str) -> None:
    try:
        payload = json.loads(text)
    except Exception:
        return

    topic = payload.get("topic")
    msg_type = payload.get("type")
    data: dict[str, Any] = payload.get("data") or {}

    # Only process events for state updates
    if msg_type != "event":
        return

    st: PeblarState = hass.data[DOMAIN][entry.entry_id]["state"]
    changed = False

    # ---- Session status (known working structure from your Safari capture)
    if topic == TOPIC_SESSION:
        new_state = data.get("state")
        if new_state != st.session_state:
            st.session_state = new_state
            changed = True

        meter = data.get("meterData") or {}
        ip = meter.get("instantaneousPower")
        te = meter.get("totalEnergy")

        if ip is not None and ip != st.instantaneous_power:
            st.instantaneous_power = ip
            changed = True
        if te is not None and te != st.total_energy:
            st.total_energy = te
            changed = True

        _update_and_notify(hass, entry, changed)
        return

    # ---- Network status (known working structure from your Safari capture)
    if topic == TOPIC_NETWORK:
        iface = data.get("interface")
        if iface == "EWlanSta":
            rssi = data.get("signalStrength")
            if rssi is not None and rssi != st.wlan_rssi:
                st.wlan_rssi = rssi
                changed = True

        if iface == "ELte":
            info = data.get("lteInfo") or {}
            carrier = info.get("carrier")
            tech = info.get("technology")
            if carrier is not None and carrier != st.lte_carrier:
                st.lte_carrier = carrier
                changed = True
            if tech is not None and tech != st.lte_technology:
                st.lte_technology = tech
                changed = True

        _update_and_notify(hass, entry, changed)
        return

    # ---- Meter topics (structure differs between firmwares; try a few common shapes)
    if topic in ("/meter/data", "/meter/status"):
        # Common shapes we've seen in other devices:
        # 1) data: { "instantaneousPower": [..], "totalEnergy": N }
        # 2) data: { "meterData": { "instantaneousPower": [..], "totalEnergy": N } }
        meter = data.get("meterData") if isinstance(data.get("meterData"), dict) else data

        if isinstance(meter, dict):
            ip = meter.get("instantaneousPower")
            te = meter.get("totalEnergy")

            if ip is not None and ip != st.instantaneous_power:
                st.instantaneous_power = ip
                changed = True
            if te is not None and te != st.total_energy:
                st.total_energy = te
                changed = True

        _update_and_notify(hass, entry, changed)
        return

    # Other topics ignored for now (diagnostics/statistics)


def _is_charging(state: PeblarState) -> bool:
    if not state.session_state:
        return False
    return "charg" in state.session_state.lower()


async def _poll_runner(hass: HomeAssistant, entry: ConfigEntry) -> None:
    host = entry.data[CONF_HOST]
    username = entry.data[CONF_USERNAME]
    password = entry.data[CONF_PASSWORD]
    base_http = f"http://{host}"
    session = async_get_clientsession(hass)

    while True:
        try:
            await _poll_once(hass, entry, session, base_http, username, password)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            _LOGGER.debug("Peblar poll error: %s", e)

        state: PeblarState = hass.data[DOMAIN][entry.entry_id]["state"]
        interval = POLL_INTERVAL_CHARGING if _is_charging(state) else POLL_INTERVAL_IDLE
        await asyncio.sleep(interval.total_seconds())


async def _poll_once(
    hass: HomeAssistant,
    entry: ConfigEntry,
    session: ClientSession,
    base_http: str,
    username: str,
    password: str,
) -> None:
    data = hass.data[DOMAIN][entry.entry_id]
    cookie = data.get("cookie")
    headers = {
        "Origin": base_http,
        "Accept": "application/json, text/plain, */*",
    }
    if cookie:
        headers["Cookie"] = cookie

    payload = await _fetch_first_payload(session, base_http, headers)
    if payload is None:
        cookie = await _login_and_get_cookie(session, base_http, username, password)
        data["cookie"] = cookie
        headers["Cookie"] = cookie
        payload = await _fetch_first_payload(session, base_http, headers)

    if payload is not None:
        _apply_poll_payload(hass, entry, payload)


async def _fetch_first_payload(
    session: ClientSession, base_http: str, headers: dict[str, str]
) -> dict[str, Any] | None:
    for endpoint in POLL_ENDPOINTS:
        url = f"{base_http}{endpoint}"
        async with session.get(url, headers=headers) as resp:
            if resp.status in (401, 403):
                return None
            if resp.status != 200:
                continue
            try:
                payload = await resp.json()
            except Exception:
                continue
            if isinstance(payload, dict):
                return payload
    return None


def _apply_poll_payload(hass: HomeAssistant, entry: ConfigEntry, payload: dict[str, Any]) -> None:
    st: PeblarState = hass.data[DOMAIN][entry.entry_id]["state"]
    changed = False

    # Some endpoints return { "state": "...", "meterData": {...} }
    new_state = payload.get("state")
    if new_state is not None and new_state != st.session_state:
        st.session_state = new_state
        changed = True

    meter = payload.get("meterData") if isinstance(payload.get("meterData"), dict) else payload
    if isinstance(meter, dict):
        ip = meter.get("instantaneousPower")
        te = meter.get("totalEnergy")
        if ip is not None and ip != st.instantaneous_power:
            st.instantaneous_power = ip
            changed = True
        if te is not None and te != st.total_energy:
            st.total_energy = te
            changed = True

    # /statistics/session returns { "data": [ { "averagePower": [...], ... }, ... ] }
    if isinstance(payload.get("data"), list) and payload["data"]:
        latest = payload["data"][0]
        if isinstance(latest, dict):
            ap = latest.get("averagePower")
            if ap is not None and ap != st.instantaneous_power:
                st.instantaneous_power = ap
                changed = True

    _update_and_notify(hass, entry, changed)
