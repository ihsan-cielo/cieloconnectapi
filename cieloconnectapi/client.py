"""Async Python API client for Cielo Home."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Mapping, Optional

from aiohttp import ClientSession, ClientTimeout, ClientResponse

from .exceptions import AuthenticationError, CieloError
from .model import CieloData, CieloDevice
from .helpers import _to_int, _to_float, _to_str_or_none, _exp_backoff

__version__ = "0.1.0"

BASE_URL = "https://devapi.smartcielo.com/openapi/v1"
DEFAULT_TIMEOUT = 5 * 60  # 5 minutes
AUTH_ERROR_CODES = {401, 403}

_LOGGER = logging.getLogger(__name__)


class CieloClient:
    """Asynchronous client for the Cielo Home API.

    Usage:
        async with CieloClient(api_key, otp) as client:
            data = await client.get_devices_data()
    """

    def __init__(
        self,
        api_key: str,
        otp: str,
        *,
        session: Optional[ClientSession] = None,
        timeout: int = DEFAULT_TIMEOUT,
        token: Optional[str] = None,
        max_retries: int = 2,
    ) -> None:
        self.api_key = api_key
        self.otp = otp
        self.token = token
        self._owned_session = session is None
        self._session: ClientSession = session or ClientSession(
            timeout=ClientTimeout(total=timeout)
        )
        self._timeout = ClientTimeout(total=timeout)
        self._max_retries = max(0, int(max_retries))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def __aenter__(self) -> CieloClient:
        if self._session.closed:
            self._session = ClientSession(timeout=self._timeout)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the session if it was created by this client."""
        if self._owned_session and not self._session.closed:
            await self._session.close()

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    async def get_or_refresh_token(self, force_refresh: bool = False) -> str:
        """Ensure an access token is available, refreshing if needed."""
        if force_refresh or not self.token:
            await self._login()
        assert self.token
        return self.token

    async def _login(self) -> None:
        """Authenticate using OTP and store the token."""
        payload = {"OTP": self.otp}
        headers = {"x-api-key": self.api_key}

        result = await self._post(
            f"{BASE_URL}/authenticate",
            json_data=payload,
            headers=headers,
            auth_ok=False,
        )
        try:
            self.token = result["data"]["accessToken"]
        except (KeyError, TypeError) as exc:
            raise AuthenticationError("Invalid authentication response format") from exc
        _LOGGER.debug("Authentication succeeded")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def get_devices_data(self) -> CieloData:
        """Fetch and parse all devices into normalized dataclasses."""
        await self.get_or_refresh_token()
        response = await self._get(f"{BASE_URL}/devices", headers=self._auth_headers())
        devices_payload = (response or {}).get("data", {}).get("devicesData", {})

        parsed: Dict[str, CieloDevice] = {}

        if isinstance(devices_payload, dict):
            for _k, devices in devices_payload.items():
                if isinstance(devices, list):
                    for d in devices:
                        self._add_device(parsed, d)
                elif isinstance(devices, dict):
                    for v in devices.values():
                        if isinstance(v, list):
                            for d in v:
                                self._add_device(parsed, d)
        elif isinstance(devices_payload, list):
            for d in devices_payload:
                self._add_device(parsed, d)

        return CieloData(raw=response, parsed=parsed)

    async def set_ac_state(
        self, mac_address: str, actions: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Send a control command to a specific AC unit."""
        await self.get_or_refresh_token()
        payload = {"macAddress": mac_address, "actions": dict(actions)}
        if "temperature" in payload["actions"]:
            payload["actions"]["temperature"] = int(payload["actions"]["temperature"])
        return await self._post(
            f"{BASE_URL}/action", json_data=payload, headers=self._auth_headers()
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _auth_headers(self) -> Dict[str, str]:
        return {"x-api-key": self.api_key, "Authorization": self.token or ""}

    def _add_device(
        self, parsed: Dict[str, CieloDevice], device: Mapping[str, Any]
    ) -> None:
        try:
            dev = self._parse_device(device)
            parsed[dev.mac_address] = dev
        except Exception as exc:
            _LOGGER.debug("Skipping device due to parse error: %s", exc)

    def _parse_device(self, device: Mapping[str, Any]) -> CieloDevice:
        env = device.get("environment") or {}
        ac_state = device.get("currentState") or {}

        unit = (device.get("temperatureUnit") or "Celsius (°C)").lower()
        temp_unit = "C" if "c" in unit else "F"

        # Parse temperature range
        min_t, max_t = 16, 30
        range_str = str(device.get("temperatureRange") or "16-30")
        try:
            a, b = range_str.split("-", 1)
            min_t, max_t = sorted((int(a), int(b)))
        except Exception:
            pass
        temp_range = list(range(min_t, max_t + 1))

        is_thermostat = "THERMOSTAT" in str(device.get("deviceType") or "").upper()

        supported_fans = list(device.get("supportedFanSpeeds") or [])
        supported_fans = [str(f).lower() for f in sorted(supported_fans)]

        supported_swings = list(device.get("supportedSwingPositions") or [])
        supported_swings = [str(s).lower() for s in sorted(supported_swings)]
        #TODO : format data from backend api
        return CieloDevice(
            id=str(device.get("macAddress") or ""),
            mac_address=str(device.get("macAddress") or ""),
            name=str(device.get("deviceName") or ""),
            ac_states=dict(ac_state),
            device_status=(str(ac_state.get("deviceStatus") or "").lower() == "online"),
            temp=_to_float(env.get("temperature")),
            humidity=_to_int(env.get("humidity")),
            target_temp=_to_float(
                ac_state.get("setPoint") or ac_state.get("temperature")
            ),
            hvac_mode=_to_str_or_none(ac_state.get("mode")),
            device_on=(str(ac_state.get("power") or "").lower() != "off"),
            fan_mode=_to_str_or_none((ac_state.get("fanSpeed") or "").lower()),
            swing_mode=_to_str_or_none((ac_state.get("swingPosition") or "").lower()),
            hvac_modes=list(device.get("supportedModes") or []),
            fan_modes=supported_fans or None,
            fan_modes_translated={f.lower(): str(f) for f in supported_fans} or None,
            swing_modes=supported_swings or None,
            swing_modes_translated={s.lower(): str(s) for s in supported_swings}
            or None,
            temp_list=temp_range,
            preset_modes=list(device.get("supportedPresets") or []) or None,
            preset_mode=_to_int(device.get("preset")),
            temp_unit=temp_unit,
            temp_step=_to_int(device.get("temperatureIncrement"), default=1),
            is_thermostat=is_thermostat,
            is_appliance_screen_less=(
                str(
                    (device.get("applianceInfo") or {}).get("applianceType") or ""
                ).lower()
                == "screenless"
            ),
        )

    # ------------------------------------------------------------------
    # HTTP core
    # ------------------------------------------------------------------
    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        json_data: Optional[Mapping[str, Any]] = None,
        retries: Optional[int] = None,
        auth_ok: bool = True,
    ) -> Dict[str, Any]:
        attempts = 0
        max_retries = self._max_retries if retries is None else max(0, int(retries))

        while True:
            attempts += 1
            try:
                async with self._session.request(
                    method,
                    url,
                    headers=headers,
                    params=dict(params) if params else None,
                    json=dict(json_data) if json_data else None,
                    timeout=self._timeout,
                ) as resp:
                    if resp.status in AUTH_ERROR_CODES and auth_ok:
                        _LOGGER.debug(
                            "Auth failed (%s). Refreshing token…", resp.status
                        )
                        await self.get_or_refresh_token(force_refresh=True)
                        if headers and "Authorization" in headers:
                            headers = dict(headers)
                            headers["Authorization"] = self.token or ""
                        continue

                    return await self._handle_response(resp)

            except AuthenticationError:
                raise
            except Exception as exc:
                if attempts <= max_retries + 1:
                    delay = _exp_backoff(attempts - 1)
                    _LOGGER.warning(
                        "Request failed (%s %s): %s. Retrying in %.2fs",
                        method,
                        url,
                        exc,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                raise CieloError(
                    f"Request failed after {attempts - 1} retries: {exc}"
                ) from exc

    async def _handle_response(self, resp: ClientResponse) -> Dict[str, Any]:
        if resp.status in AUTH_ERROR_CODES:
            raise AuthenticationError(f"Authentication failed (HTTP {resp.status})")
        if resp.status != 200:
            text = await resp.text()
            raise CieloError(f"HTTP {resp.status}: {text}")

        try:
            return await resp.json()
        except Exception as exc:
            raise CieloError(f"Invalid JSON response: {exc}") from exc

    async def _get(self, url: str, **kwargs) -> Dict[str, Any]:
        return await self._request("GET", url, **kwargs)

    async def _post(self, url: str, **kwargs) -> Dict[str, Any]:
        return await self._request("POST", url, **kwargs)
