"""Data classes for Cielo."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional


@dataclass(slots=True)
class CieloData:
    """Container for raw response and parsed device map keyed by MAC."""

    raw: Optional[Mapping[str, Any]]
    parsed: Optional[Dict[str, "CieloDevice"]]


@dataclass(slots=True)
class CieloDevice:
    """Normalized view of a Cielo device."""

    id: str
    mac_address: str
    name: str

    # Current states / environment
    ac_states: Mapping[str, Any]
    device_status: Optional[bool]
    temp: Optional[float]
    humidity: Optional[int]
    target_temp: Optional[float]
    hvac_mode: Optional[str]
    device_on: Optional[bool]

    # Capabilities & metadata
    is_thermostat: Optional[bool]
    fan_mode: Optional[str]
    swing_mode: Optional[str]
    hvac_modes: Optional[List[str]]
    fan_modes: Optional[List[str]]
    fan_modes_translated: Optional[Dict[str, str]]
    swing_modes: Optional[List[str]]
    swing_modes_translated: Optional[Dict[str, str]]
    temp_list: List[int]
    preset_modes: Optional[List[str]]
    preset_mode: Optional[int]
    temp_unit: Optional[str]
    temp_step: Optional[int]
    is_appliance_screen_less: Optional[bool]
