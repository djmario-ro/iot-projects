"""Admin-only reader configuration using HA's existing Matter fabric."""
import asyncio
import re
import json
from urllib.parse import urlsplit

import voluptuous as vol
from homeassistant.components.matter.helpers import get_matter, node_from_ha_device_id
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.service import async_register_admin_service

from .protocol import checked_key, decode, encode, valid_name

DOMAIN = "doorkey"
CONFIG_SCHEMA = vol.Schema({DOMAIN: vol.Schema({})}, extra=vol.ALLOW_EXTRA)
BASE_SCHEMA = {vol.Required("device_id"): cv.string, vol.Optional("endpoint", default=1): vol.All(vol.Coerce(int), vol.Range(min=1, max=65534)), vol.Required("ble_name"): valid_name}


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    lock = asyncio.Lock()

    def target(data):
        node = node_from_ha_device_id(hass, data["device_id"])
        if node is None:
            raise HomeAssistantError("Select the H2 Matter device")
        attributes = node.node_data.attributes
        if attributes.get("0/40/1") != "DoorKey Prototype" or attributes.get("0/40/3") != "BLE Access Button":
            raise HomeAssistantError("Selected device is not the DoorKey H2 reader")
        adapter = get_matter(hass)
        client = getattr(adapter, "matter_client", adapter)
        return client, node.node_id, f"{data['endpoint']}/65/0"

    async def read(client, node, path):
        result = await client.read_attribute(node, path)
        if not isinstance(result, dict) or path not in result:
            raise HomeAssistantError("Reader did not return its UserLabel settings")
        return result[path]

    async def write(client, node, path, labels):
        result = await client.write_attribute(node, path, [{"0": item["label"], "1": item["value"]} for item in labels])
        if not isinstance(result, list) or not result or any(r.get("Status", r.get("status", -1)) != 0 for r in result):
            raise HomeAssistantError("Matter configuration write was not acknowledged")
        # Confirm the device's value, not only the server's optimistic cache.
        actual = await read(client, node, path)
        if decode(actual) != decode(labels):
            raise HomeAssistantError("Reader configuration read-back did not match")

    async def rename(call: ServiceCall):
        async with lock:
            try:
                client, node, path = target(call.data)
                _, key = decode(await read(client, node, path))
                await write(client, node, path, encode(call.data["ble_name"], key))
            except HomeAssistantError:
                raise
            except Exception as err:
                raise HomeAssistantError("Could not rename reader: " + str(err)) from err

    async def configure(call: ServiceCall):
        async with lock:
            try:
                url = urlsplit(call.data["manager_url"])
                if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/") or url.port not in (None, 443):
                    raise ValueError("Use the HTTPS manager origin without a path, credentials or custom port")
                fingerprint = call.data["expected_sha256"].lower()
                if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                    raise ValueError("Expected SHA-256 must be 64 hexadecimal characters")
                client, node, path = target(call.data)
                # Reject non-H2 endpoints and do not overwrite unrelated user labels.
                existing = await read(client, node, path)
                if existing:
                    decode(existing)
                session = async_get_clientsession(hass)
                async with session.get(url.geturl().rstrip("/") + "/v1/config", allow_redirects=False, timeout=10) as response:
                    if response.status != 200:
                        raise ValueError("Manager configuration unavailable")
                    raw = await response.content.read(2049)
                    if len(raw) > 2048:
                        raise ValueError("Manager response too large")
                    config = json.loads(raw)
                if config.get("protocol") != 2:
                    raise ValueError("Manager must support protocol 2")
                key = checked_key(config.get("issuerPublicKey"), fingerprint)
                await write(client, node, path, encode(call.data["ble_name"], key))
            except HomeAssistantError:
                raise
            except Exception as err:
                raise HomeAssistantError("Reader configuration failed: " + str(err)) from err

    async_register_admin_service(hass, DOMAIN, "set_ble_name", rename, schema=vol.Schema(BASE_SCHEMA))
    async_register_admin_service(hass, DOMAIN, "configure_reader", configure, schema=vol.Schema({**BASE_SCHEMA, vol.Required("manager_url"): cv.string, vol.Required("expected_sha256"): cv.string}))
    return True
