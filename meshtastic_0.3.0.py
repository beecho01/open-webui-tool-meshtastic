"""
title: Meshtastic
author: James Beeching
version: 0.3.0
license: GPLv3
description: Feature-rich Open WebUI Workspace Tool for inspecting, diagnosing, messaging and safely administering a Meshtastic node over Wi-Fi/TCP.
requirements: meshtastic==2.7.11
"""

from __future__ import annotations

import asyncio
import base64
import json
import math
import socket
import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as package_version
from typing import Any, Callable, Dict, List, Optional, Tuple

from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import Message
from pydantic import BaseModel, Field

from meshtastic import BROADCAST_ADDR
from meshtastic.protobuf import channel_pb2, mesh_pb2, portnums_pb2, telemetry_pb2
from meshtastic.tcp_interface import TCPInterface
from meshtastic.util import fromPSK, pskToString


class Tools:
    """Open WebUI tools for a Meshtastic node reachable over TCP/Wi-Fi."""

    LOCAL_CONFIG_SECTIONS = {
        "device",
        "position",
        "power",
        "network",
        "display",
        "lora",
        "bluetooth",
        "security",
    }

    MODULE_CONFIG_SECTIONS = {
        "mqtt",
        "serial",
        "external_notification",
        "store_forward",
        "range_test",
        "telemetry",
        "canned_message",
        "audio",
        "remote_hardware",
        "neighbor_info",
        "detection_sensor",
        "ambient_lighting",
        "paxcounter",
        "traffic_management",
    }

    SENSITIVE_KEY_FRAGMENTS = {
        "psk",
        "password",
        "private_key",
        "privatekey",
        "admin_key",
        "adminkey",
        "wifi_psk",
        "wifipsk",
        "secret",
        "token",
    }

    TELEMETRY_TYPES = {
        "device_metrics",
        "environment_metrics",
        "air_quality_metrics",
        "power_metrics",
        "local_stats",
    }


    # RF planning data mirrors the current Meshtastic firmware region table as of
    # 2026-08-22. It is used for deterministic planning only; local law and the
    # radio hardware's actual PA limit always take precedence.
    RF_DATA_REVISION = "2026-08-22"

    RF_REGION_PROFILES: Dict[str, Dict[str, Any]] = {
        "US": {"start": 902.0, "end": 928.0, "duty": 100.0, "power": 30.0, "spacing": 0.0, "padding": 0.0, "profile": "STD", "reg_basis": "ERP", "reg_limit": 30.0},
        "EU_433": {"start": 433.0, "end": 434.0, "duty": 10.0, "power": 10.0, "spacing": 0.0, "padding": 0.0, "profile": "STD", "reg_basis": "ERP", "reg_limit": 10.0},
        "EU_868": {"start": 869.4, "end": 869.65, "duty": 10.0, "power": 27.0, "spacing": 0.0, "padding": 0.0, "profile": "EU868", "reg_basis": "ERP", "reg_limit": 27.0},
        "EU_866": {"start": 865.6, "end": 867.6, "duty": 2.5, "power": 27.0, "spacing": 0.4, "padding": 0.0375, "profile": "LITE"},
        "EU_N_868": {"start": 869.4, "end": 869.65, "duty": 10.0, "power": 27.0, "spacing": 0.0, "padding": 0.0104, "profile": "NARROW", "override_slot": 1},
        "CN": {"start": 470.0, "end": 510.0, "duty": 100.0, "power": 19.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "JP": {"start": 920.5, "end": 923.5, "duty": 100.0, "power": 13.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "ANZ": {"start": 915.0, "end": 928.0, "duty": 100.0, "power": 30.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "ANZ_433": {"start": 433.05, "end": 434.79, "duty": 100.0, "power": 14.0, "spacing": 0.0, "padding": 0.0, "profile": "STD", "reg_basis": "EIRP", "reg_limit": 14.0},
        "RU": {"start": 868.7, "end": 869.2, "duty": 100.0, "power": 20.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "KR": {"start": 920.0, "end": 923.0, "duty": 100.0, "power": 23.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "TW": {"start": 920.0, "end": 925.0, "duty": 100.0, "power": 27.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "IN": {"start": 865.0, "end": 867.0, "duty": 100.0, "power": 30.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "NZ_865": {"start": 864.0, "end": 868.0, "duty": 100.0, "power": 36.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "TH": {"start": 920.0, "end": 925.0, "duty": 10.0, "power": 27.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "UA_433": {"start": 433.0, "end": 434.7, "duty": 10.0, "power": 10.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "MY_433": {"start": 433.0, "end": 435.0, "duty": 100.0, "power": 20.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "MY_919": {"start": 919.0, "end": 924.0, "duty": 100.0, "power": 27.0, "spacing": 0.0, "padding": 0.0, "profile": "STD", "frequency_switching": True},
        "SG_923": {"start": 917.0, "end": 925.0, "duty": 100.0, "power": 20.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "PH_433": {"start": 433.0, "end": 434.7, "duty": 100.0, "power": 10.0, "spacing": 0.0, "padding": 0.0, "profile": "STD", "reg_basis": "ERP", "reg_limit": 10.0},
        "PH_868": {"start": 868.0, "end": 869.4, "duty": 100.0, "power": 14.0, "spacing": 0.0, "padding": 0.0, "profile": "STD", "reg_basis": "ERP", "reg_limit": 14.0},
        "PH_915": {"start": 915.0, "end": 918.0, "duty": 100.0, "power": 24.0, "spacing": 0.0, "padding": 0.0, "profile": "STD", "reg_basis": "EIRP", "reg_limit": 24.0, "note": "Firmware source notes that external antennas are not allowed for this regional profile."},
        "KZ_433": {"start": 433.075, "end": 434.775, "duty": 100.0, "power": 10.0, "spacing": 0.0, "padding": 0.0, "profile": "STD", "reg_basis": "EIRP", "reg_limit": 10.0},
        "KZ_863": {"start": 863.0, "end": 868.0, "duty": 100.0, "power": 30.0, "spacing": 0.0, "padding": 0.0, "profile": "STD", "reg_basis": "EIRP", "reg_limit": 14.0, "note": "Firmware's regional TX ceiling is 30 dBm, but its regulatory source comment states <25 mW EIRP; the planner therefore uses 14 dBm EIRP for the radiated-power check."},
        "NP_865": {"start": 865.0, "end": 868.0, "duty": 100.0, "power": 30.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "BR_902": {"start": 902.0, "end": 907.5, "duty": 100.0, "power": 30.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "ITU1_2M": {"start": 144.0, "end": 146.0, "duty": 100.0, "power": 30.0, "spacing": 0.0, "padding": 0.0022, "profile": "HAM_20KHZ", "override_slot": 26, "licensed_only": True},
        "ITU2_2M": {"start": 144.0, "end": 148.0, "duty": 100.0, "power": 30.0, "spacing": 0.0, "padding": 0.0022, "profile": "HAM_20KHZ", "override_slot": 51, "licensed_only": True},
        "ITU3_2M": {"start": 144.0, "end": 148.0, "duty": 100.0, "power": 30.0, "spacing": 0.0, "padding": 0.0022, "profile": "HAM_20KHZ", "override_slot": 33, "licensed_only": True},
        "ITU2_125CM": {"start": 220.0, "end": 225.0, "duty": 100.0, "power": 30.0, "spacing": 0.0, "padding": 0.01875, "profile": "HAM_100KHZ", "override_slot": 37, "licensed_only": True},
        "ITU1_70CM": {"start": 430.0, "end": 440.0, "duty": 100.0, "power": 30.0, "spacing": 0.0, "padding": 0.01875, "profile": "HAM_100KHZ", "override_slot": 37, "licensed_only": True},
        "ITU2_70CM": {"start": 420.0, "end": 450.0, "duty": 100.0, "power": 30.0, "spacing": 0.0, "padding": 0.01875, "profile": "HAM_100KHZ", "override_slot": 137, "licensed_only": True},
        "ITU3_70CM": {"start": 430.0, "end": 450.0, "duty": 100.0, "power": 30.0, "spacing": 0.0, "padding": 0.01875, "profile": "HAM_100KHZ", "override_slot": 37, "licensed_only": True},
        "LORA_24": {"start": 2400.0, "end": 2483.5, "duty": 100.0, "power": 10.0, "spacing": 0.0, "padding": 0.0, "profile": "STD"},
        "UNSET": {"start": 902.0, "end": 928.0, "duty": 100.0, "power": 30.0, "spacing": 0.0, "padding": 0.0, "profile": "UNDEF"},
    }

    # Primary presets use the published Meshtastic link-budget values where available;
    # newer specialised presets use the current firmware modem parameter mapping.
    # Custom mode always prefers the live bandwidth/SF/CR values from the device.
    RF_MODEM_PRESETS: Dict[str, Dict[str, Any]] = {
        "SHORT_TURBO": {"bandwidth_khz": 500.0, "wide_bandwidth_khz": 1625.0, "sf": 7, "cr": 5, "documented_link_budget_db": 140.0, "channel_name": "ShortTurbo"},
        "SHORT_FAST": {"bandwidth_khz": 250.0, "wide_bandwidth_khz": 812.5, "sf": 7, "cr": 5, "documented_link_budget_db": 143.0, "channel_name": "ShortFast"},
        "SHORT_SLOW": {"bandwidth_khz": 250.0, "wide_bandwidth_khz": 812.5, "sf": 8, "cr": 5, "documented_link_budget_db": 145.5, "channel_name": "ShortSlow"},
        "MEDIUM_FAST": {"bandwidth_khz": 250.0, "wide_bandwidth_khz": 812.5, "sf": 9, "cr": 5, "documented_link_budget_db": 148.0, "channel_name": "MediumFast"},
        "MEDIUM_SLOW": {"bandwidth_khz": 250.0, "wide_bandwidth_khz": 812.5, "sf": 10, "cr": 5, "documented_link_budget_db": 150.5, "channel_name": "MediumSlow"},
        "MEDIUM_TURBO": {"bandwidth_khz": 500.0, "wide_bandwidth_khz": 1625.0, "sf": 9, "cr": 5, "channel_name": "MediumTurbo"},
        "LONG_TURBO": {"bandwidth_khz": 500.0, "wide_bandwidth_khz": 1625.0, "sf": 11, "cr": 8, "documented_link_budget_db": 150.0, "channel_name": "LongTurbo"},
        "LONG_FAST": {"bandwidth_khz": 250.0, "wide_bandwidth_khz": 812.5, "sf": 11, "cr": 5, "documented_link_budget_db": 153.0, "channel_name": "LongFast"},
        "LONG_MODERATE": {"bandwidth_khz": 125.0, "wide_bandwidth_khz": 406.25, "sf": 11, "cr": 8, "documented_link_budget_db": 156.0, "channel_name": "LongMod"},
        "LONG_SLOW": {"bandwidth_khz": 125.0, "wide_bandwidth_khz": 406.25, "sf": 12, "cr": 8, "documented_link_budget_db": 158.5, "channel_name": "LongSlow", "deprecated": True},
        "LITE_FAST": {"bandwidth_khz": 125.0, "sf": 9, "cr": 5, "channel_name": "LiteFast"},
        "LITE_SLOW": {"bandwidth_khz": 125.0, "sf": 10, "cr": 5, "channel_name": "LiteSlow"},
        "NARROW_FAST": {"bandwidth_khz": 62.5, "sf": 7, "cr": 6, "channel_name": "NarrowFast"},
        "NARROW_SLOW": {"bandwidth_khz": 62.5, "sf": 8, "cr": 6, "channel_name": "NarrowSlow"},
        "TINY_FAST": {"bandwidth_khz": 15.6, "sf": 7, "cr": 5, "channel_name": "TinyFast"},
        "TINY_SLOW": {"bandwidth_khz": 15.6, "sf": 8, "cr": 6, "channel_name": "TinySlow"},
    }

    RF_SNR_THRESHOLDS_DB = {
        5: -2.5,
        6: -5.0,
        7: -7.5,
        8: -10.0,
        9: -12.5,
        10: -15.0,
        11: -17.5,
        12: -20.0,
    }

    class Valves(BaseModel):
        host: str = Field(
            default="192.168.1.60",
            description="IP address or hostname of the Meshtastic device on your LAN.",
        )
        port: int = Field(
            default=4403,
            ge=1,
            le=65535,
            description="Meshtastic TCP port. The standard port is 4403.",
        )
        connect_timeout_seconds: float = Field(
            default=5.0,
            ge=0.5,
            le=30.0,
            description="Timeout used for the TCP reachability pre-check.",
        )
        default_channel_index: int = Field(
            default=0,
            ge=0,
            le=7,
            description="Default Meshtastic channel index for messaging and requests.",
        )
        default_traceroute_hops: int = Field(
            default=3,
            ge=1,
            le=7,
            description="Default hop limit for traceroute requests.",
        )
        max_message_bytes: int = Field(
            default=200,
            ge=1,
            le=230,
            description="Maximum UTF-8 message size this tool will send. Kept conservative for LoRa payloads.",
        )
        max_listen_seconds: int = Field(
            default=30,
            ge=1,
            le=120,
            description="Maximum duration allowed for the listen_for_packets tool.",
        )

        redact_secrets: bool = Field(
            default=True,
            description="Redact PSKs, passwords, private keys and similar secrets from tool output.",
        )
        redact_positions: bool = Field(
            default=False,
            description="Redact latitude/longitude values returned to the LLM.",
        )
        allow_secret_output: bool = Field(
            default=False,
            description="Allow outputs that inherently contain channel secrets, such as Meshtastic share URLs.",
        )

        allow_messages: bool = Field(
            default=False,
            description="Allow the tool to send Meshtastic text messages.",
        )
        allow_alerts: bool = Field(
            default=False,
            description="Allow high-priority Meshtastic alert messages. Requires allow_messages too.",
        )
        allow_config_writes: bool = Field(
            default=False,
            description="Allow local device/module configuration writes.",
        )
        allow_channel_writes: bool = Field(
            default=False,
            description="Allow channel settings to be changed or channels to be deleted/imported.",
        )
        allow_sensitive_config_writes: bool = Field(
            default=False,
            description="Allow changes to security-sensitive fields such as PSKs/private keys/passwords.",
        )
        allow_region_changes: bool = Field(
            default=False,
            description="Allow changing LoRa region. Disabled separately because region controls regulatory radio parameters.",
        )
        allow_position_writes: bool = Field(
            default=False,
            description="Allow setting/removing a fixed device position.",
        )
        allow_nodedb_writes: bool = Field(
            default=False,
            description="Allow favourite/ignore/remove/reset operations on the local NodeDB.",
        )
        allow_admin_actions: bool = Field(
            default=False,
            description="Allow administrative actions such as reboot, shutdown and clock synchronisation.",
        )
        confirm_mutations: bool = Field(
            default=True,
            description="Require an interactive Open WebUI confirmation before mutating the device.",
        )

    def __init__(self):
        self.valves = self.Valves()
        self._operation_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Core helpers
    # ------------------------------------------------------------------

    def _json(self, data: Any) -> str:
        return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False)

    async def _status(self, emitter, description: str, done: bool = False) -> None:
        if emitter:
            try:
                await emitter(
                    {
                        "type": "status",
                        "data": {
                            "description": description,
                            "done": done,
                            "hidden": done,
                        },
                    }
                )
            except Exception:
                # Status UI is optional and should never make the radio operation fail.
                pass

    async def _confirm(self, event_call, title: str, message: str) -> bool:
        if not self.valves.confirm_mutations:
            return True
        if not event_call:
            return False
        try:
            result = await event_call(
                {
                    "type": "confirmation",
                    "data": {"title": title, "message": message},
                }
            )
            if isinstance(result, dict):
                if "confirmed" in result:
                    return bool(result["confirmed"])
                if "value" in result:
                    return bool(result["value"])
            return bool(result)
        except Exception:
            return False

    async def _run_sync(
        self,
        func: Callable[[], Any],
        emitter=None,
        start_status: str = "Connecting to Meshtastic device…",
        done_status: str = "Meshtastic operation complete",
    ) -> str:
        async with self._operation_lock:
            await self._status(emitter, start_status, False)
            try:
                result = await asyncio.to_thread(func)
                await self._status(emitter, done_status, True)
                return self._json({"ok": True, "result": result})
            except SystemExit as exc:
                await self._status(emitter, "Meshtastic operation failed", True)
                return self._json(
                    {
                        "ok": False,
                        "error": "Meshtastic library aborted the operation",
                        "details": str(exc),
                    }
                )
            except Exception as exc:
                await self._status(emitter, "Meshtastic operation failed", True)
                return self._json(
                    {
                        "ok": False,
                        "error": type(exc).__name__,
                        "details": str(exc),
                    }
                )

    def _preflight(self) -> None:
        host = self.valves.host.strip()
        if not host:
            raise ValueError("Meshtastic host is empty. Set the tool's host Valve first.")
        with socket.create_connection(
            (host, int(self.valves.port)),
            timeout=float(self.valves.connect_timeout_seconds),
        ):
            pass

    def _with_interface(self, func: Callable[[TCPInterface], Any], no_nodes: bool = False) -> Any:
        self._preflight()
        iface: Optional[TCPInterface] = None
        try:
            iface = TCPInterface(
                hostname=self.valves.host.strip(),
                portNumber=int(self.valves.port),
                noNodes=no_nodes,
            )
            return func(iface)
        finally:
            if iface is not None:
                try:
                    iface.close()
                except Exception:
                    pass

    def _proto_to_dict(self, message: Optional[Message]) -> Any:
        if message is None:
            return None
        kwargs = {
            "preserving_proto_field_name": True,
            "use_integers_for_enums": False,
        }
        try:
            return MessageToDict(
                message,
                always_print_fields_with_no_presence=True,
                **kwargs,
            )
        except TypeError:
            # Compatibility with older protobuf releases.
            try:
                return MessageToDict(
                    message,
                    including_default_value_fields=True,
                    **kwargs,
                )
            except TypeError:
                return MessageToDict(message, **kwargs)

    def _is_sensitive_key(self, key: str) -> bool:
        normalized = key.lower().replace("-", "_")
        return any(fragment in normalized for fragment in self.SENSITIVE_KEY_FRAGMENTS)

    def _clean_data(self, value: Any, key_hint: str = "") -> Any:
        if self.valves.redact_secrets and key_hint and self._is_sensitive_key(key_hint):
            return "[REDACTED_SECRET]"

        if self.valves.redact_positions and key_hint.lower() in {
            "latitude",
            "longitude",
            "latitude_i",
            "longitude_i",
        }:
            return "[REDACTED_POSITION]"

        if isinstance(value, Message):
            return self._clean_data(self._proto_to_dict(value), key_hint)
        if isinstance(value, bytes):
            if self.valves.redact_secrets and self._is_sensitive_key(key_hint):
                return "[REDACTED_SECRET]"
            return "base64:" + base64.b64encode(value).decode("ascii")
        if isinstance(value, dict):
            cleaned = {}
            for key, val in value.items():
                if str(key) in {"raw", "payload"}:
                    # Raw packet payloads are normally duplicate/unfriendly binary data.
                    continue
                cleaned[str(key)] = self._clean_data(val, str(key))
            return cleaned
        if isinstance(value, (list, tuple, set)):
            return [self._clean_data(item, key_hint) for item in value]
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(value)

    def _timestamp_iso(self, timestamp: Any) -> Optional[str]:
        try:
            ts = int(timestamp)
            if ts <= 0:
                return None
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except Exception:
            return None

    def _augment_node(self, node: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(node)
        last_heard = result.get("lastHeard")
        if last_heard is not None:
            result["lastHeardIsoUtc"] = self._timestamp_iso(last_heard)
            try:
                result["ageSeconds"] = max(0, int(time.time()) - int(last_heard))
            except Exception:
                pass
        return self._clean_data(result)

    def _find_node_entry(self, iface: TCPInterface, node_ref: str) -> Tuple[str, Dict[str, Any]]:
        nodes = iface.nodes or {}
        ref = str(node_ref).strip()
        if not ref:
            raise ValueError("Node reference is empty")

        if ref in nodes:
            return ref, nodes[ref]

        # Accept !abcdef12, decimal node number, long name or short name.
        if ref.startswith("!"):
            target_num = int(ref[1:], 16)
            for key, node in nodes.items():
                if int(node.get("num", -1)) == target_num:
                    return key, node
        elif ref.isdigit():
            target_num = int(ref)
            for key, node in nodes.items():
                if int(node.get("num", -1)) == target_num:
                    return key, node

        matches: List[Tuple[str, Dict[str, Any]]] = []
        needle = ref.casefold()
        for key, node in nodes.items():
            user = node.get("user") or {}
            candidates = {
                str(key),
                str(user.get("id", "")),
                str(user.get("longName", "")),
                str(user.get("shortName", "")),
            }
            if any(candidate.casefold() == needle for candidate in candidates if candidate):
                matches.append((key, node))

        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ValueError(f"Node reference '{node_ref}' is ambiguous")
        raise ValueError(f"Node '{node_ref}' was not found in the local NodeDB")

    def _resolve_destination(self, iface: TCPInterface, destination: str) -> Any:
        ref = str(destination).strip()
        if ref.casefold() in {"all", "broadcast", "^all"}:
            return BROADCAST_ADDR
        try:
            key, node = self._find_node_entry(iface, ref)
            user = node.get("user") or {}
            return user.get("id") or key
        except ValueError:
            # A valid explicit node ID may not yet exist in our NodeDB.
            if ref.startswith("!"):
                int(ref[1:], 16)  # validates hex
                return ref
            if ref.isdigit():
                return int(ref)
            raise

    def _get_config_message(self, iface: TCPInterface, section: str) -> Tuple[str, Message]:
        name = section.strip().lower()
        local = iface.localNode
        if name in self.LOCAL_CONFIG_SECTIONS and hasattr(local.localConfig, name):
            return "local", getattr(local.localConfig, name)
        if name in self.MODULE_CONFIG_SECTIONS and hasattr(local.moduleConfig, name):
            return "module", getattr(local.moduleConfig, name)
        raise ValueError(
            f"Unknown config section '{section}'. Valid local sections: "
            f"{', '.join(sorted(self.LOCAL_CONFIG_SECTIONS))}; module sections: "
            f"{', '.join(sorted(self.MODULE_CONFIG_SECTIONS))}."
        )

    def _field_type_name(self, field: FieldDescriptor) -> str:
        type_map = {
            FieldDescriptor.TYPE_DOUBLE: "double",
            FieldDescriptor.TYPE_FLOAT: "float",
            FieldDescriptor.TYPE_INT64: "int64",
            FieldDescriptor.TYPE_UINT64: "uint64",
            FieldDescriptor.TYPE_INT32: "int32",
            FieldDescriptor.TYPE_FIXED64: "fixed64",
            FieldDescriptor.TYPE_FIXED32: "fixed32",
            FieldDescriptor.TYPE_BOOL: "bool",
            FieldDescriptor.TYPE_STRING: "string",
            FieldDescriptor.TYPE_GROUP: "group",
            FieldDescriptor.TYPE_MESSAGE: "message",
            FieldDescriptor.TYPE_BYTES: "bytes",
            FieldDescriptor.TYPE_UINT32: "uint32",
            FieldDescriptor.TYPE_ENUM: "enum",
            FieldDescriptor.TYPE_SFIXED32: "sfixed32",
            FieldDescriptor.TYPE_SFIXED64: "sfixed64",
            FieldDescriptor.TYPE_SINT32: "sint32",
            FieldDescriptor.TYPE_SINT64: "sint64",
        }
        return type_map.get(field.type, str(field.type))

    def _describe_message(self, message: Message, prefix: str = "") -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for field in message.DESCRIPTOR.fields:
            path = f"{prefix}.{field.name}" if prefix else field.name
            row: Dict[str, Any] = {
                "field": path,
                "type": self._field_type_name(field),
                "repeated": field.label == FieldDescriptor.LABEL_REPEATED,
            }
            if field.enum_type is not None:
                row["enumValues"] = [value.name for value in field.enum_type.values]
            try:
                current = getattr(message, field.name)
                if field.type == FieldDescriptor.TYPE_MESSAGE and field.label != FieldDescriptor.LABEL_REPEATED:
                    nested = self._describe_message(current, path)
                    row["fields"] = nested
                else:
                    row["currentValue"] = self._clean_data(current, field.name)
            except Exception:
                pass
            rows.append(row)
        return rows

    def _resolve_proto_field(
        self, message: Message, field_path: str
    ) -> Tuple[Message, FieldDescriptor]:
        parts = [part.strip() for part in field_path.split(".") if part.strip()]
        if not parts:
            raise ValueError("Field path is empty")

        parent: Message = message
        for part in parts[:-1]:
            field = parent.DESCRIPTOR.fields_by_name.get(part)
            if field is None:
                raise ValueError(f"Unknown field '{part}' in '{field_path}'")
            if field.type != FieldDescriptor.TYPE_MESSAGE or field.label == FieldDescriptor.LABEL_REPEATED:
                raise ValueError(f"'{part}' is not a traversable message field")
            parent = getattr(parent, part)

        field = parent.DESCRIPTOR.fields_by_name.get(parts[-1])
        if field is None:
            raise ValueError(f"Unknown field '{parts[-1]}' in '{field_path}'")
        return parent, field

    def _parse_text_value(self, value: str) -> Any:
        text = str(value).strip()
        try:
            return json.loads(text)
        except Exception:
            return text

    def _coerce_scalar(self, field: FieldDescriptor, value: Any) -> Any:
        if field.type == FieldDescriptor.TYPE_ENUM:
            if isinstance(value, int):
                if field.enum_type.values_by_number.get(value) is None:
                    raise ValueError(f"{value} is not a valid enum value for {field.name}")
                return value
            text = str(value).strip()
            if text.lstrip("-").isdigit():
                number = int(text)
                if field.enum_type.values_by_number.get(number) is None:
                    raise ValueError(f"{number} is not a valid enum value for {field.name}")
                return number
            target = text.upper()
            for enum_value in field.enum_type.values:
                if enum_value.name.upper() == target:
                    return enum_value.number
            valid = ", ".join(v.name for v in field.enum_type.values)
            raise ValueError(f"Invalid enum '{value}' for {field.name}. Valid values: {valid}")

        if field.type == FieldDescriptor.TYPE_BOOL:
            if isinstance(value, bool):
                return value
            text = str(value).strip().lower()
            if text in {"true", "1", "yes", "on"}:
                return True
            if text in {"false", "0", "no", "off"}:
                return False
            raise ValueError(f"'{value}' is not a valid boolean")

        if field.type in {
            FieldDescriptor.TYPE_INT32,
            FieldDescriptor.TYPE_INT64,
            FieldDescriptor.TYPE_UINT32,
            FieldDescriptor.TYPE_UINT64,
            FieldDescriptor.TYPE_FIXED32,
            FieldDescriptor.TYPE_FIXED64,
            FieldDescriptor.TYPE_SFIXED32,
            FieldDescriptor.TYPE_SFIXED64,
            FieldDescriptor.TYPE_SINT32,
            FieldDescriptor.TYPE_SINT64,
        }:
            return int(value)

        if field.type in {FieldDescriptor.TYPE_FLOAT, FieldDescriptor.TYPE_DOUBLE}:
            numeric = float(value)
            if not math.isfinite(numeric):
                raise ValueError("Numeric value must be finite")
            return numeric

        if field.type == FieldDescriptor.TYPE_STRING:
            return str(value)

        if field.type == FieldDescriptor.TYPE_BYTES:
            if isinstance(value, bytes):
                return value
            text = str(value)
            if text.startswith("base64:"):
                return base64.b64decode(text[7:], validate=True)
            if text.startswith("0x"):
                return bytes.fromhex(text[2:])
            raise ValueError("Byte fields must use base64:<data> or 0x<hex>")

        raise ValueError(
            f"Setting protobuf field type '{self._field_type_name(field)}' is not supported"
        )

    def _set_proto_value(self, message: Message, field_path: str, value_text: str) -> Dict[str, Any]:
        parent, field = self._resolve_proto_field(message, field_path)
        raw_value = self._parse_text_value(value_text)

        old_value = getattr(parent, field.name)
        old_clean = self._clean_data(old_value, field.name)

        if field.type == FieldDescriptor.TYPE_MESSAGE:
            raise ValueError(
                "Set a scalar sub-field rather than replacing an entire protobuf message"
            )

        if field.label == FieldDescriptor.LABEL_REPEATED:
            values = raw_value if isinstance(raw_value, list) else [raw_value]
            coerced = [self._coerce_scalar(field, item) for item in values]
            container = getattr(parent, field.name)
            del container[:]
            container.extend(coerced)
            new_value: Any = list(container)
        else:
            new_value = self._coerce_scalar(field, raw_value)
            setattr(parent, field.name, new_value)

        return {
            "field": field_path,
            "type": self._field_type_name(field),
            "oldValue": old_clean,
            "newValue": self._clean_data(getattr(parent, field.name), field.name),
        }

    def _validate_write_permission(self, section: str, field_path: str) -> None:
        if not self.valves.allow_config_writes:
            raise PermissionError("Configuration writes are disabled in this tool's Valves")

        section_name = section.strip().lower()
        if section_name == "security" or self._is_sensitive_key(field_path):
            if not self.valves.allow_sensitive_config_writes:
                raise PermissionError(
                    "Sensitive configuration writes are disabled in this tool's Valves"
                )

        if section_name == "lora" and field_path.strip().lower() == "region":
            if not self.valves.allow_region_changes:
                raise PermissionError(
                    "LoRa region changes are disabled in this tool's Valves"
                )

    def _config_preview_sync(self, section: str, field_path: str, value: str) -> Dict[str, Any]:
        def op(iface: TCPInterface) -> Dict[str, Any]:
            scope, message = self._get_config_message(iface, section)
            proposal = self._set_proto_value(message, field_path, value)
            proposal["section"] = section.strip().lower()
            proposal["scope"] = scope
            proposal["writeEnabled"] = bool(self.valves.allow_config_writes)
            proposal["requiresSensitiveWritePermission"] = bool(
                section.strip().lower() == "security" or self._is_sensitive_key(field_path)
            )
            proposal["requiresRegionWritePermission"] = bool(
                section.strip().lower() == "lora"
                and field_path.strip().lower() == "region"
            )
            proposal["applied"] = False
            return proposal

        return self._with_interface(op)

    def _apply_config_sync(self, section: str, field_path: str, value: str) -> Dict[str, Any]:
        self._validate_write_permission(section, field_path)

        def op(iface: TCPInterface) -> Dict[str, Any]:
            scope, message = self._get_config_message(iface, section)
            change = self._set_proto_value(message, field_path, value)
            iface.localNode.writeConfig(section.strip().lower())
            time.sleep(0.2)
            return {
                "section": section.strip().lower(),
                "scope": scope,
                **change,
                "applied": True,
            }

        return self._with_interface(op)

    def _parse_batch(self, changes_json: str) -> List[Dict[str, str]]:
        try:
            raw = json.loads(changes_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"changes_json is not valid JSON: {exc}") from exc
        if not isinstance(raw, list) or not raw:
            raise ValueError("changes_json must be a non-empty JSON array")
        if len(raw) > 30:
            raise ValueError("A maximum of 30 config changes can be applied in one batch")

        parsed: List[Dict[str, str]] = []
        for index, item in enumerate(raw):
            if not isinstance(item, dict):
                raise ValueError(f"Batch item {index} is not an object")
            section = str(item.get("section", "")).strip()
            field_path = str(item.get("field", item.get("field_path", ""))).strip()
            if "value" not in item:
                raise ValueError(f"Batch item {index} has no value")
            value = item["value"]
            if isinstance(value, str):
                value_text = value
            else:
                value_text = json.dumps(value, separators=(",", ":"))
            if not section or not field_path:
                raise ValueError(f"Batch item {index} requires section and field")
            parsed.append(
                {"section": section, "field": field_path, "value": value_text}
            )
        return parsed

    # ------------------------------------------------------------------
    # RF planning helpers (read-only)
    # ------------------------------------------------------------------

    def _rf_float(self, value: Any, default: Optional[float] = None) -> Optional[float]:
        try:
            numeric = float(value)
            return numeric if math.isfinite(numeric) else default
        except Exception:
            return default

    def _rf_bandwidth_khz(self, value: Any) -> Optional[float]:
        numeric = self._rf_float(value)
        if numeric is None or numeric <= 0:
            return None
        encoded = {
            8.0: 7.8,
            10.0: 10.4,
            16.0: 15.6,
            21.0: 20.8,
            31.0: 31.25,
            42.0: 41.7,
            62.0: 62.5,
            200.0: 203.125,
            400.0: 406.25,
            800.0: 812.5,
            1600.0: 1625.0,
        }
        return encoded.get(numeric, numeric)

    def _rf_djb2(self, value: str) -> int:
        result = 5381
        for byte in str(value).encode("utf-8"):
            result = ((result * 33) + byte) & 0xFFFFFFFF
        return result

    def _rf_primary_channel_name(self, iface: TCPInterface, preset_name: str) -> str:
        try:
            for channel in iface.localNode.channels or []:
                try:
                    role = channel_pb2.Channel.Role.Name(channel.role)
                except Exception:
                    role = str(channel.role)
                if role == "PRIMARY":
                    settings = getattr(channel, "settings", None)
                    name = str(getattr(settings, "name", "") or "").strip()
                    if name:
                        return name
        except Exception:
            pass
        preset = self.RF_MODEM_PRESETS.get(preset_name) or {}
        return str(preset.get("channel_name") or preset_name.replace("_", "").title())

    def _rf_modem_profile(self, lora: Dict[str, Any], wide_lora: bool = False) -> Dict[str, Any]:
        preset_name = str(lora.get("modem_preset") or "LONG_FAST").upper()
        use_preset = bool(lora.get("use_preset", True))
        warnings: List[str] = []

        if use_preset and preset_name in self.RF_MODEM_PRESETS:
            result = dict(self.RF_MODEM_PRESETS[preset_name])
            if wide_lora and result.get("wide_bandwidth_khz"):
                result["bandwidth_khz"] = result["wide_bandwidth_khz"]
            result.pop("wide_bandwidth_khz", None)
            live_cr = int(self._rf_float(lora.get("coding_rate"), 0) or 0)
            if 5 <= live_cr <= 8 and live_cr > int(result.get("cr") or 0):
                result["cr"] = live_cr
                result["coding_rate_source"] = "live higher custom coding_rate over preset"
            else:
                result["coding_rate_source"] = "preset"
            result.update({"source": "Meshtastic preset", "preset": preset_name, "usePreset": True})
            return result

        bandwidth = self._rf_bandwidth_khz(lora.get("bandwidth"))
        sf = int(self._rf_float(lora.get("spread_factor"), 0) or 0)
        cr = int(self._rf_float(lora.get("coding_rate"), 0) or 0)
        if bandwidth and 5 <= sf <= 12 and 5 <= cr <= 8:
            if use_preset:
                warnings.append(
                    f"Preset {preset_name} is newer than this planner's documented preset table; using the live bandwidth/SF/CR fields reported by the device."
                )
            return {
                "source": "live LoRa fields",
                "preset": preset_name,
                "usePreset": use_preset,
                "bandwidth_khz": bandwidth,
                "sf": sf,
                "cr": cr,
                "warnings": warnings,
            }

        if use_preset:
            warnings.append(
                f"Preset {preset_name} is not in the planner table and the device did not expose usable bandwidth/SF/CR values. Frequency and sensitivity calculations may need an explicit override."
            )
        else:
            warnings.append("Custom LoRa settings did not expose valid bandwidth, spreading factor and coding rate values.")
        return {
            "source": "incomplete live LoRa fields",
            "preset": preset_name,
            "usePreset": use_preset,
            "bandwidth_khz": bandwidth,
            "sf": sf or None,
            "cr": cr or None,
            "warnings": warnings,
        }

    def _rf_node_position(self, node: Dict[str, Any]) -> Optional[Tuple[float, float]]:
        position = node.get("position") or {}
        lat = self._rf_float(position.get("latitude"))
        lon = self._rf_float(position.get("longitude"))
        if lat is None:
            raw = self._rf_float(position.get("latitudeI", position.get("latitude_i")))
            lat = raw / 1e7 if raw is not None else None
        if lon is None:
            raw = self._rf_float(position.get("longitudeI", position.get("longitude_i")))
            lon = raw / 1e7 if raw is not None else None
        if lat is None or lon is None or not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
            return None
        return lat, lon

    def _rf_haversine_km(self, a: Tuple[float, float], b: Tuple[float, float]) -> float:
        lat1, lon1 = map(math.radians, a)
        lat2, lon2 = map(math.radians, b)
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
        return 6371.0088 * 2 * math.atan2(math.sqrt(h), math.sqrt(max(0.0, 1.0 - h)))

    def _rf_context_from_iface(self, iface: TCPInterface) -> Dict[str, Any]:
        lora = self._proto_to_dict(iface.localNode.localConfig.lora) or {}
        if not isinstance(lora, dict):
            lora = {}
        region_name = str(lora.get("region") or "UNSET").upper()
        region = dict(self.RF_REGION_PROFILES.get(region_name) or {})
        modem = self._rf_modem_profile(lora, wide_lora=(region_name == "LORA_24"))
        warnings: List[str] = list(modem.get("warnings") or [])

        if not region:
            warnings.append(
                f"Region {region_name} is not in RF_DATA_REVISION {self.RF_DATA_REVISION}; supply frequency_mhz explicitly and verify current local rules."
            )
        if region_name == "UNSET":
            warnings.append("LoRa region is UNSET. Do not use the regional power/frequency defaults as permission to transmit.")

        device_cfg = self._proto_to_dict(iface.localNode.localConfig.device) or {}
        role = str(device_cfg.get("role") or "") if isinstance(device_cfg, dict) else ""
        duty = region.get("duty")
        if region_name == "EU_866" and role.upper() in {"ROUTER", "ROUTER_LATE"}:
            duty = 10.0

        configured_tx = self._rf_float(lora.get("tx_power"), 0.0) or 0.0
        firmware_cap = self._rf_float(region.get("power"))
        planning_tx = configured_tx if configured_tx > 0 else firmware_cap
        if configured_tx <= 0 and firmware_cap is not None:
            tx_source = "region default / firmware power ceiling"
        elif configured_tx > 0:
            tx_source = "live configured tx_power"
        else:
            tx_source = "unknown"

        offset = self._rf_float(lora.get("frequency_offset"), 0.0) or 0.0
        override_frequency = self._rf_float(lora.get("override_frequency"), 0.0) or 0.0
        configured_slot = int(self._rf_float(lora.get("channel_num"), 0.0) or 0)
        frequency = None
        slot_one_based = None
        slots = None
        slot_width_mhz = None
        channel_name = self._rf_primary_channel_name(iface, str(modem.get("preset") or "LONG_FAST"))

        bandwidth_khz = self._rf_float(modem.get("bandwidth_khz"))
        if override_frequency > 0:
            frequency = override_frequency + offset
            frequency_source = "live override_frequency + frequency_offset"
        elif region and bandwidth_khz:
            slot_width_mhz = (
                float(region.get("spacing", 0.0))
                + (2.0 * float(region.get("padding", 0.0)))
                + bandwidth_khz / 1000.0
            )
            if slot_width_mhz > 0:
                slots = max(1, int(round((float(region["end"]) - float(region["start"]) + float(region.get("spacing", 0.0))) / slot_width_mhz)))
                if configured_slot > 0:
                    slot_one_based = configured_slot
                    frequency_source = "live channel_num"
                elif int(region.get("override_slot", 0) or 0) > 0:
                    slot_one_based = int(region["override_slot"])
                    frequency_source = "region default slot"
                else:
                    slot_one_based = (self._rf_djb2(channel_name) % slots) + 1
                    frequency_source = "Meshtastic channel-name hash"
                slot_index = max(0, min(slots - 1, slot_one_based - 1))
                frequency = (
                    float(region["start"])
                    + bandwidth_khz / 2000.0
                    + float(region.get("padding", 0.0))
                    + slot_index * slot_width_mhz
                    + offset
                )
            else:
                frequency_source = "unknown"
        else:
            frequency_source = "unknown"

        if region.get("licensed_only"):
            warnings.append("This is an amateur/licensed region profile. Licence privileges and the applicable band plan take precedence over generic planner limits.")
        if region.get("note"):
            warnings.append(str(region["note"]))
        if region.get("frequency_switching"):
            warnings.append("This region uses frequency switching; a single calculated centre frequency does not describe all transmissions.")

        return {
            "dataRevision": self.RF_DATA_REVISION,
            "region": region_name,
            "frequencyMHz": round(frequency, 6) if frequency is not None else None,
            "frequencySource": frequency_source,
            "frequencyOffsetMHz": offset,
            "overrideFrequencyMHz": override_frequency or None,
            "frequencySlot": slot_one_based,
            "frequencySlotCount": slots,
            "frequencySlotWidthMHz": round(slot_width_mhz, 6) if slot_width_mhz is not None else None,
            "primaryChannelNameForHash": channel_name,
            "modem": {
                "preset": modem.get("preset"),
                "usePreset": modem.get("usePreset"),
                "source": modem.get("source"),
                "bandwidthKHz": bandwidth_khz,
                "spreadingFactor": modem.get("sf"),
                "codingRate": f"4/{modem.get('cr')}" if modem.get("cr") else None,
                "codingRateSource": modem.get("coding_rate_source"),
                "documentedLinkBudgetDb": modem.get("documented_link_budget_db"),
            },
            "tx": {
                "enabled": bool(lora.get("tx_enabled", True)),
                "configuredTxPowerDbm": configured_tx,
                "planningTxPowerDbm": planning_tx,
                "planningTxPowerSource": tx_source,
                "firmwareRegionPowerLimitDbm": firmware_cap,
                "hardwareActualTxPowerKnown": False,
                "note": "Meshtastic configuration does not guarantee the radio hardware can produce the regional ceiling. Pass actual_tx_power_dbm when known for a more accurate link budget.",
            },
            "regionProfile": {
                "bandStartMHz": region.get("start"),
                "bandEndMHz": region.get("end"),
                "dutyCyclePercent": duty,
                "firmwarePowerLimitDbm": firmware_cap,
                "regulatoryRadiatedPowerBasis": region.get("reg_basis"),
                "regulatoryRadiatedPowerLimitDbm": region.get("reg_limit"),
                "licensedOnly": bool(region.get("licensed_only", False)),
            },
            "warnings": warnings,
        }

    def _rf_receiver_sensitivity_dbm(
        self,
        bandwidth_khz: Optional[float],
        sf: Optional[int],
        noise_figure_db: float = 6.0,
    ) -> Optional[float]:
        if not bandwidth_khz or not sf or sf not in self.RF_SNR_THRESHOLDS_DB:
            return None
        noise_floor = -174.0 + 10.0 * math.log10(bandwidth_khz * 1000.0) + noise_figure_db
        return noise_floor + self.RF_SNR_THRESHOLDS_DB[sf]

    def _rf_regulatory_assessment(
        self,
        context: Dict[str, Any],
        tx_power_dbm: float,
        antenna_gain_dbi: float,
        cable_loss_db: float,
    ) -> Dict[str, Any]:
        eirp = tx_power_dbm - cable_loss_db + antenna_gain_dbi
        erp = eirp - 2.15
        region = context.get("regionProfile") or {}
        basis = region.get("regulatoryRadiatedPowerBasis")
        limit = self._rf_float(region.get("regulatoryRadiatedPowerLimitDbm"))
        licensed = bool(region.get("licensedOnly"))
        result: Dict[str, Any] = {
            "eirpDbm": round(eirp, 2),
            "erpDbm": round(erp, 2),
            "basis": basis,
            "radiatedPowerLimitDbm": limit,
            "status": "not_assessed",
            "planningOnly": True,
        }
        if licensed:
            result["status"] = "licensed_profile_check_local_band_plan"
            return result
        if basis in {"EIRP", "ERP"} and limit is not None:
            radiated = eirp if basis == "EIRP" else erp
            headroom = limit - radiated
            max_tx = limit - antenna_gain_dbi + cable_loss_db
            if basis == "ERP":
                max_tx += 2.15
            result.update(
                {
                    "radiatedPowerDbm": round(radiated, 2),
                    "headroomDb": round(headroom, 2),
                    "maximumTxDbmForThisAntennaSystem": round(max_tx, 2),
                    "conservativeWholeDbmTxSetting": math.floor(max_tx),
                    "status": "within_planner_limit" if headroom >= -1e-9 else "exceeds_planner_limit",
                }
            )
        return result

    def _rf_link_budget(
        self,
        distance_km: float,
        frequency_mhz: float,
        tx_power_dbm: float,
        tx_antenna_gain_dbi: float,
        rx_antenna_gain_dbi: float,
        tx_cable_loss_db: float,
        rx_cable_loss_db: float,
        receiver_sensitivity_dbm: float,
        fade_margin_db: float,
        extra_path_loss_db: float,
    ) -> Dict[str, Any]:
        fspl = 32.44 + 20.0 * math.log10(distance_km) + 20.0 * math.log10(frequency_mhz)
        received = (
            tx_power_dbm
            + tx_antenna_gain_dbi
            - tx_cable_loss_db
            + rx_antenna_gain_dbi
            - rx_cable_loss_db
            - fspl
            - extra_path_loss_db
        )
        raw_margin = received - receiver_sensitivity_dbm
        fade_adjusted_margin = raw_margin - fade_margin_db
        return {
            "freeSpacePathLossDb": round(fspl, 2),
            "predictedReceivePowerDbm": round(received, 2),
            "receiverSensitivityDbm": round(receiver_sensitivity_dbm, 2),
            "rawLinkMarginDb": round(raw_margin, 2),
            "targetFadeMarginDb": round(fade_margin_db, 2),
            "marginAfterFadeAllowanceDb": round(fade_adjusted_margin, 2),
            "extraPathLossAssumptionDb": round(extra_path_loss_db, 2),
            "assessment": (
                "positive theoretical margin"
                if fade_adjusted_margin >= 0
                else "negative theoretical margin"
            ),
        }

    def _rf_geometry(
        self,
        distance_km: float,
        frequency_mhz: float,
        tx_height_m: float,
        rx_height_m: float,
    ) -> Dict[str, Any]:
        f_ghz = frequency_mhz / 1000.0
        d1 = distance_km / 2.0
        d2 = distance_km / 2.0
        fresnel = 17.32 * math.sqrt((d1 * d2) / (max(f_ghz, 1e-9) * distance_km))
        horizon = None
        if tx_height_m > 0 and rx_height_m > 0:
            horizon = 4.12 * (math.sqrt(tx_height_m) + math.sqrt(rx_height_m))
        return {
            "firstFresnelRadiusAtMidpointM": round(fresnel, 2),
            "recommended60PercentFresnelClearanceM": round(fresnel * 0.6, 2),
            "approximateRadioHorizonKm": round(horizon, 2) if horizon is not None else None,
            "radioHorizonModel": "4/3-earth approximation" if horizon is not None else None,
            "note": "Fresnel and radio-horizon figures are geometry checks, not terrain/path-profile analysis.",
        }

    def _rf_validate_numeric(self, name: str, value: float, minimum: Optional[float] = None) -> float:
        numeric = float(value)
        if not math.isfinite(numeric):
            raise ValueError(f"{name} must be finite")
        if minimum is not None and numeric < minimum:
            raise ValueError(f"{name} must be at least {minimum}")
        return numeric

    # ------------------------------------------------------------------
    # Information and diagnostics
    # ------------------------------------------------------------------

    async def get_tool_info(self) -> str:
        """Return MeshOps version, Meshtastic Python version, target host and enabled capability gates."""
        try:
            meshtastic_version = package_version("meshtastic")
        except PackageNotFoundError:
            meshtastic_version = "unknown"
        return self._json(
            {
                "ok": True,
                "result": {
                    "tool": "MeshOps - Meshtastic WiFi",
                    "toolVersion": "0.3.0",
                    "meshtasticPythonVersion": meshtastic_version,
                    "host": self.valves.host,
                    "port": self.valves.port,
                    "capabilities": {
                        "messages": self.valves.allow_messages,
                        "alerts": self.valves.allow_alerts,
                        "configWrites": self.valves.allow_config_writes,
                        "channelWrites": self.valves.allow_channel_writes,
                        "sensitiveWrites": self.valves.allow_sensitive_config_writes,
                        "regionChanges": self.valves.allow_region_changes,
                        "positionWrites": self.valves.allow_position_writes,
                        "nodeDbWrites": self.valves.allow_nodedb_writes,
                        "adminActions": self.valves.allow_admin_actions,
                        "interactiveConfirmation": self.valves.confirm_mutations,
                        "rfPlanning": True,
                    },
                },
            }
        )

    async def test_connection(self, __event_emitter__=None) -> str:
        """Test TCP and Meshtastic protocol connectivity to the configured Wi-Fi node."""

        def run() -> Dict[str, Any]:
            started = time.monotonic()

            def op(iface: TCPInterface) -> Dict[str, Any]:
                return {
                    "reachable": True,
                    "protocolConnected": bool(iface.isConnected.is_set()),
                    "metadata": self._clean_data(iface.metadata),
                    "myInfo": self._clean_data(iface.myInfo),
                    "elapsedSeconds": round(time.monotonic() - started, 3),
                }

            return self._with_interface(op, no_nodes=True)

        return await self._run_sync(
            run,
            __event_emitter__,
            "Testing Meshtastic Wi-Fi connection…",
            "Meshtastic connection test complete",
        )

    async def get_device_summary(self, __event_emitter__=None) -> str:
        """Get a concise local-device health summary: firmware/hardware, owner, telemetry, radio settings and NodeDB count."""

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                my_node = iface.getMyNodeInfo() or {}
                local = iface.localNode
                channels = local.channels or []
                active_channels = 0
                for channel in channels:
                    try:
                        role = channel_pb2.Channel.Role.Name(channel.role)
                    except Exception:
                        role = str(channel.role)
                    if role != "DISABLED":
                        active_channels += 1

                return {
                    "owner": {
                        "longName": iface.getLongName(),
                        "shortName": iface.getShortName(),
                    },
                    "metadata": self._clean_data(iface.metadata),
                    "myInfo": self._clean_data(iface.myInfo),
                    "localNode": self._augment_node(my_node) if isinstance(my_node, dict) else self._clean_data(my_node),
                    "knownNodeCountIncludingSelf": len(iface.nodes or {}),
                    "activeChannelCount": active_channels,
                    "selectedConfig": {
                        "device": self._clean_data(local.localConfig.device),
                        "lora": self._clean_data(local.localConfig.lora),
                        "power": self._clean_data(local.localConfig.power),
                        "network": self._clean_data(local.localConfig.network),
                        "telemetry": self._clean_data(local.moduleConfig.telemetry),
                    },
                    "rfPlanning": self._rf_context_from_iface(iface),
                }

            return self._with_interface(op)

        return await self._run_sync(
            run,
            __event_emitter__,
            "Reading Meshtastic device health…",
            "Device health loaded",
        )

    async def get_nodes(
        self,
        active_within_minutes: int = 0,
        include_self: bool = True,
        sort_by: str = "last_heard",
        max_nodes: int = 100,
        __event_emitter__=None,
    ) -> str:
        """
        List nodes known by the local Meshtastic NodeDB.

        sort_by may be last_heard, snr, hops, battery or name.
        active_within_minutes=0 disables age filtering.
        """

        def run() -> Dict[str, Any]:
            if active_within_minutes < 0:
                raise ValueError("active_within_minutes cannot be negative")
            if max_nodes < 1 or max_nodes > 500:
                raise ValueError("max_nodes must be between 1 and 500")
            valid_sort = {"last_heard", "snr", "hops", "battery", "name"}
            sort_key = sort_by.strip().lower()
            if sort_key not in valid_sort:
                raise ValueError(f"sort_by must be one of: {', '.join(sorted(valid_sort))}")

            def op(iface: TCPInterface) -> Dict[str, Any]:
                now = int(time.time())
                my_num = None
                try:
                    my_info = iface.getMyNodeInfo() or {}
                    my_num = my_info.get("num")
                except Exception:
                    pass

                rows: List[Dict[str, Any]] = []
                for key, node in (iface.nodes or {}).items():
                    if not include_self and my_num is not None and node.get("num") == my_num:
                        continue
                    if active_within_minutes > 0:
                        last = int(node.get("lastHeard") or 0)
                        if last <= 0 or now - last > active_within_minutes * 60:
                            continue
                    row = dict(node)
                    row["nodeDbKey"] = key
                    rows.append(row)

                def battery(row: Dict[str, Any]) -> float:
                    return float((row.get("deviceMetrics") or {}).get("batteryLevel") or -1)

                if sort_key == "last_heard":
                    rows.sort(key=lambda r: int(r.get("lastHeard") or 0), reverse=True)
                elif sort_key == "snr":
                    rows.sort(key=lambda r: float(r.get("snr") or -999), reverse=True)
                elif sort_key == "hops":
                    rows.sort(key=lambda r: int(r.get("hopsAway") if r.get("hopsAway") is not None else 999))
                elif sort_key == "battery":
                    rows.sort(key=battery, reverse=True)
                else:
                    rows.sort(key=lambda r: str((r.get("user") or {}).get("longName") or "").casefold())

                rows = rows[:max_nodes]
                return {
                    "count": len(rows),
                    "activeWithinMinutes": active_within_minutes or None,
                    "nodes": [self._augment_node(row) for row in rows],
                }

            return self._with_interface(op)

        return await self._run_sync(
            run,
            __event_emitter__,
            "Reading Meshtastic NodeDB…",
            "NodeDB loaded",
        )

    async def search_nodes(self, query: str, __event_emitter__=None) -> str:
        """Find NodeDB entries by node ID, decimal node number, long name or short name."""

        def run() -> Dict[str, Any]:
            needle = query.strip().casefold()
            if not needle:
                raise ValueError("Search query is empty")

            def op(iface: TCPInterface) -> Dict[str, Any]:
                matches = []
                for key, node in (iface.nodes or {}).items():
                    user = node.get("user") or {}
                    haystacks = [
                        str(key),
                        str(node.get("num", "")),
                        str(user.get("id", "")),
                        str(user.get("longName", "")),
                        str(user.get("shortName", "")),
                    ]
                    if any(needle in hay.casefold() for hay in haystacks if hay):
                        row = dict(node)
                        row["nodeDbKey"] = key
                        matches.append(self._augment_node(row))
                return {"query": query, "count": len(matches), "nodes": matches}

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Searching NodeDB…", "Node search complete")

    async def get_node(self, node: str, __event_emitter__=None) -> str:
        """Get detailed NodeDB information for one node by ID, number, long name or short name."""

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                key, entry = self._find_node_entry(iface, node)
                result = dict(entry)
                result["nodeDbKey"] = key
                return self._augment_node(result)

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Reading node details…", "Node details loaded")

    async def get_mesh_health(
        self,
        active_within_minutes: int = 60,
        __event_emitter__=None,
    ) -> str:
        """Calculate mesh diagnostic statistics from the local NodeDB without changing the radio."""

        def run() -> Dict[str, Any]:
            if active_within_minutes < 1 or active_within_minutes > 10080:
                raise ValueError("active_within_minutes must be between 1 and 10080")

            def op(iface: TCPInterface) -> Dict[str, Any]:
                now = int(time.time())
                my_info = iface.getMyNodeInfo() or {}
                my_num = my_info.get("num")
                nodes = list((iface.nodes or {}).values())
                peers = [n for n in nodes if my_num is None or n.get("num") != my_num]
                active = [
                    n
                    for n in peers
                    if int(n.get("lastHeard") or 0) > 0
                    and now - int(n.get("lastHeard") or 0) <= active_within_minutes * 60
                ]
                snrs = [float(n["snr"]) for n in active if n.get("snr") is not None]
                hops = [int(n["hopsAway"]) for n in active if n.get("hopsAway") is not None]
                direct = [n for n in active if n.get("hopsAway") == 0]
                via_mqtt = [n for n in active if bool(n.get("viaMqtt"))]

                low_battery = []
                for node in active:
                    metrics = node.get("deviceMetrics") or {}
                    battery = metrics.get("batteryLevel")
                    if battery is not None:
                        try:
                            if 0 <= float(battery) < 20:
                                low_battery.append(
                                    {
                                        "id": (node.get("user") or {}).get("id"),
                                        "name": (node.get("user") or {}).get("longName"),
                                        "batteryLevel": battery,
                                    }
                                )
                        except Exception:
                            pass

                weakest = sorted(
                    [n for n in active if n.get("snr") is not None],
                    key=lambda n: float(n.get("snr")),
                )[:5]

                return {
                    "windowMinutes": active_within_minutes,
                    "knownPeerCount": len(peers),
                    "activePeerCount": len(active),
                    "directActivePeerCount": len(direct),
                    "activeViaMqttCount": len(via_mqtt),
                    "snr": {
                        "samples": len(snrs),
                        "min": min(snrs) if snrs else None,
                        "max": max(snrs) if snrs else None,
                        "average": round(sum(snrs) / len(snrs), 2) if snrs else None,
                    },
                    "hops": {
                        "samples": len(hops),
                        "min": min(hops) if hops else None,
                        "max": max(hops) if hops else None,
                        "average": round(sum(hops) / len(hops), 2) if hops else None,
                    },
                    "localMetrics": self._clean_data(my_info.get("deviceMetrics") or {}),
                    "lowBatteryPeersBelow20Percent": self._clean_data(low_battery),
                    "weakestRecentSnrNodes": [
                        self._clean_data(
                            {
                                "id": (n.get("user") or {}).get("id"),
                                "name": (n.get("user") or {}).get("longName"),
                                "snr": n.get("snr"),
                                "hopsAway": n.get("hopsAway"),
                                "lastHeard": n.get("lastHeard"),
                                "lastHeardIsoUtc": self._timestamp_iso(n.get("lastHeard")),
                            }
                        )
                        for n in weakest
                    ],
                }

            return self._with_interface(op)

        return await self._run_sync(
            run,
            __event_emitter__,
            "Analysing Meshtastic mesh health…",
            "Mesh health analysis complete",
        )

    async def rf_analyse_link(
        self,
        node: str = "",
        distance_km: float = 0.0,
        frequency_mhz: float = 0.0,
        tx_antenna_gain_dbi: float = 0.0,
        rx_antenna_gain_dbi: float = 0.0,
        tx_cable_loss_db: float = 0.0,
        rx_cable_loss_db: float = 0.0,
        tx_height_m: float = 0.0,
        rx_height_m: float = 0.0,
        fade_margin_db: float = 10.0,
        extra_path_loss_db: float = 0.0,
        actual_tx_power_dbm: Optional[float] = None,
        receiver_sensitivity_dbm: Optional[float] = None,
        __event_emitter__=None,
    ) -> str:
        """
        Analyse a Meshtastic/LoRa link using the live local radio configuration.

        Give node to derive distance from NodeDB positions when available, or give
        distance_km explicitly. Optional frequency_mhz, actual_tx_power_dbm and
        receiver_sensitivity_dbm override planner estimates. Antenna gains are dBi;
        cable/path losses and fade margin are dB. This is a planning model, not a
        terrain survey or guarantee of connectivity.
        """

        def run() -> Dict[str, Any]:
            explicit_distance = self._rf_validate_numeric("distance_km", distance_km, 0.0)
            explicit_frequency = self._rf_validate_numeric("frequency_mhz", frequency_mhz, 0.0)
            tx_gain = self._rf_validate_numeric("tx_antenna_gain_dbi", tx_antenna_gain_dbi)
            rx_gain = self._rf_validate_numeric("rx_antenna_gain_dbi", rx_antenna_gain_dbi)
            tx_loss = self._rf_validate_numeric("tx_cable_loss_db", tx_cable_loss_db, 0.0)
            rx_loss = self._rf_validate_numeric("rx_cable_loss_db", rx_cable_loss_db, 0.0)
            tx_height = self._rf_validate_numeric("tx_height_m", tx_height_m, 0.0)
            rx_height = self._rf_validate_numeric("rx_height_m", rx_height_m, 0.0)
            fade = self._rf_validate_numeric("fade_margin_db", fade_margin_db, 0.0)
            extra_loss = self._rf_validate_numeric("extra_path_loss_db", extra_path_loss_db, 0.0)

            def op(iface: TCPInterface) -> Dict[str, Any]:
                context = self._rf_context_from_iface(iface)
                warnings: List[str] = list(context.get("warnings") or [])
                target: Optional[Dict[str, Any]] = None
                derived_distance = None

                if node.strip():
                    key, entry = self._find_node_entry(iface, node)
                    user = entry.get("user") or {}
                    target = {
                        "nodeDbKey": key,
                        "id": user.get("id"),
                        "name": user.get("longName"),
                        "shortName": user.get("shortName"),
                        "snrDb": entry.get("snr"),
                        "hopsAway": entry.get("hopsAway"),
                        "viaMqtt": bool(entry.get("viaMqtt")),
                        "lastHeardIsoUtc": self._timestamp_iso(entry.get("lastHeard")),
                    }
                    local_pos = self._rf_node_position(iface.getMyNodeInfo() or {})
                    remote_pos = self._rf_node_position(entry)
                    if local_pos and remote_pos:
                        derived_distance = self._rf_haversine_km(local_pos, remote_pos)
                    if target["viaMqtt"]:
                        warnings.append("Target was learned via MQTT; NodeDB SNR/distance should not be interpreted as a direct RF path measurement.")
                    hops = target.get("hopsAway")
                    if hops not in (None, 0):
                        warnings.append("Target is multi-hop. Endpoint distance is not the distance of any single RF hop, and its stored SNR is not a direct end-to-end link-budget measurement.")

                distance = explicit_distance if explicit_distance > 0 else derived_distance
                if distance is None or distance <= 0:
                    raise ValueError("Provide distance_km > 0, or name a NodeDB node where both local and remote positions are available")

                frequency = explicit_frequency if explicit_frequency > 0 else self._rf_float(context.get("frequencyMHz"))
                if frequency is None or frequency <= 0:
                    raise ValueError("The live radio frequency could not be derived. Provide frequency_mhz explicitly")

                tx_context = context.get("tx") or {}
                if actual_tx_power_dbm is not None:
                    tx_power = self._rf_validate_numeric("actual_tx_power_dbm", actual_tx_power_dbm)
                    tx_source = "explicit actual_tx_power_dbm"
                else:
                    tx_power = self._rf_float(tx_context.get("planningTxPowerDbm"))
                    if tx_power is None:
                        raise ValueError("TX power could not be derived. Provide actual_tx_power_dbm explicitly")
                    tx_source = str(tx_context.get("planningTxPowerSource") or "live configuration")
                    warnings.append("TX power is based on configuration/firmware limits, not a measured PA output. Supply actual_tx_power_dbm when the hardware maximum is known.")

                modem = context.get("modem") or {}
                if receiver_sensitivity_dbm is not None:
                    sensitivity = self._rf_validate_numeric("receiver_sensitivity_dbm", receiver_sensitivity_dbm)
                    sensitivity_source = "explicit receiver_sensitivity_dbm"
                else:
                    sensitivity = self._rf_receiver_sensitivity_dbm(
                        self._rf_float(modem.get("bandwidthKHz")),
                        int(modem.get("spreadingFactor")) if modem.get("spreadingFactor") else None,
                    )
                    if sensitivity is None:
                        raise ValueError("Receiver sensitivity could not be estimated from the live modem settings. Provide receiver_sensitivity_dbm explicitly")
                    sensitivity_source = "thermal-noise estimate using 6 dB noise figure and LoRa SF SNR threshold"
                    warnings.append("Receiver sensitivity is an engineering estimate; use the radio/module datasheet value when available.")

                budget = self._rf_link_budget(
                    distance,
                    frequency,
                    tx_power,
                    tx_gain,
                    rx_gain,
                    tx_loss,
                    rx_loss,
                    sensitivity,
                    fade,
                    extra_loss,
                )
                budget["txPowerDbm"] = round(tx_power, 2)
                budget["txPowerSource"] = tx_source
                budget["receiverSensitivitySource"] = sensitivity_source
                budget["distanceKm"] = round(distance, 3)
                budget["distanceSource"] = "explicit" if explicit_distance > 0 else "NodeDB positions"
                budget["frequencyMHz"] = round(frequency, 6)
                budget["frequencySource"] = "explicit" if explicit_frequency > 0 else context.get("frequencySource")

                regulatory = self._rf_regulatory_assessment(context, tx_power, tx_gain, tx_loss)
                if regulatory.get("status") == "exceeds_planner_limit":
                    warnings.append("The antenna/cable/TX combination exceeds the planner's radiated-power limit for this region. Reduce TX power and verify local rules before transmitting.")
                elif regulatory.get("status") == "not_assessed":
                    warnings.append("No radiated-power compliance basis is encoded for this region. The firmware TX ceiling is not a substitute for checking local EIRP/ERP rules.")

                return {
                    "radioProfile": context,
                    "target": target,
                    "linkBudget": budget,
                    "geometry": self._rf_geometry(distance, frequency, tx_height, rx_height),
                    "regulatoryPlanningCheck": regulatory,
                    "assumptions": {
                        "txAntennaGainDbi": tx_gain,
                        "rxAntennaGainDbi": rx_gain,
                        "txCableLossDb": tx_loss,
                        "rxCableLossDb": rx_loss,
                        "extraPathLossDb": extra_loss,
                    },
                    "warnings": list(dict.fromkeys(warnings)),
                }

            return self._with_interface(op)

        return await self._run_sync(
            run,
            __event_emitter__,
            "Analysing Meshtastic RF link…",
            "RF link analysis complete",
        )

    async def rf_compare_antennas(
        self,
        antennas_json: str,
        baseline_gain_dbi: float = 0.0,
        baseline_cable_loss_db: float = 0.0,
        actual_tx_power_dbm: Optional[float] = None,
        __event_emitter__=None,
    ) -> str:
        """
        Compare candidate TX antenna systems against the live Meshtastic radio settings.

        antennas_json must be a JSON array such as:
        [{"name":"5 dBi outdoor","gain_dbi":5,"cable_loss_db":1.2,"price_gbp":25}]
        Extra fields are preserved for the LLM. Results show net RF improvement,
        EIRP/ERP and a regional planning check; they do not invent a distance gain.
        """

        def run() -> Dict[str, Any]:
            try:
                candidates = json.loads(antennas_json)
            except json.JSONDecodeError as exc:
                raise ValueError(f"antennas_json is not valid JSON: {exc}") from exc
            if not isinstance(candidates, list) or not candidates:
                raise ValueError("antennas_json must be a non-empty JSON array")
            if len(candidates) > 25:
                raise ValueError("A maximum of 25 antenna candidates can be compared at once")

            baseline_gain = self._rf_validate_numeric("baseline_gain_dbi", baseline_gain_dbi)
            baseline_loss = self._rf_validate_numeric("baseline_cable_loss_db", baseline_cable_loss_db, 0.0)
            baseline_net = baseline_gain - baseline_loss

            def op(iface: TCPInterface) -> Dict[str, Any]:
                context = self._rf_context_from_iface(iface)
                tx_context = context.get("tx") or {}
                if actual_tx_power_dbm is not None:
                    tx_power = self._rf_validate_numeric("actual_tx_power_dbm", actual_tx_power_dbm)
                    tx_source = "explicit actual_tx_power_dbm"
                else:
                    tx_power = self._rf_float(tx_context.get("planningTxPowerDbm"))
                    if tx_power is None:
                        raise ValueError("TX power could not be derived. Provide actual_tx_power_dbm explicitly")
                    tx_source = str(tx_context.get("planningTxPowerSource") or "live configuration")

                rows = []
                overall_warnings: List[str] = list(context.get("warnings") or [])
                if actual_tx_power_dbm is None:
                    overall_warnings.append("TX power is based on configuration/firmware limits, not measured hardware output.")

                for index, item in enumerate(candidates):
                    if not isinstance(item, dict):
                        raise ValueError(f"Antenna item {index} is not an object")
                    name = str(item.get("name") or f"Candidate {index + 1}")
                    gain = self._rf_validate_numeric(f"{name}.gain_dbi", item.get("gain_dbi", 0.0))
                    loss = self._rf_validate_numeric(f"{name}.cable_loss_db", item.get("cable_loss_db", 0.0), 0.0)
                    net = gain - loss
                    regulatory = self._rf_regulatory_assessment(context, tx_power, gain, loss)
                    row = dict(item)
                    row.update(
                        {
                            "name": name,
                            "gainDbi": gain,
                            "cableLossDb": loss,
                            "netTxAntennaSystemDb": round(net, 2),
                            "changeVsBaselineDb": round(net - baseline_net, 2),
                            "eirpDbm": regulatory.get("eirpDbm"),
                            "erpDbm": regulatory.get("erpDbm"),
                            "regulatoryPlanningCheck": regulatory,
                        }
                    )
                    candidate_warnings = []
                    if gain >= 8.0:
                        candidate_warnings.append("High-gain omni: verify the manufacturer's vertical radiation pattern; more gain is not automatically better for nearby or elevation-diverse nodes.")
                    if regulatory.get("status") == "exceeds_planner_limit":
                        candidate_warnings.append("This candidate exceeds the encoded regional radiated-power planning limit at the assumed TX power.")
                    if candidate_warnings:
                        row["warnings"] = candidate_warnings
                    rows.append(row)

                return {
                    "radioProfile": context,
                    "txPowerDbmUsed": round(tx_power, 2),
                    "txPowerSource": tx_source,
                    "baseline": {
                        "gainDbi": baseline_gain,
                        "cableLossDb": baseline_loss,
                        "netTxAntennaSystemDb": round(baseline_net, 2),
                    },
                    "candidates": rows,
                    "interpretation": "changeVsBaselineDb is a link-budget change, not a fixed multiplier or guaranteed distance increase.",
                    "warnings": list(dict.fromkeys(overall_warnings)),
                }

            return self._with_interface(op)

        return await self._run_sync(
            run,
            __event_emitter__,
            "Comparing antenna systems against live Meshtastic settings…",
            "Antenna comparison complete",
        )

    async def rf_plan_link(
        self,
        distance_km: float,
        frequency_mhz: float = 0.0,
        tx_antenna_gain_dbi: float = 0.0,
        rx_antenna_gain_dbi: float = 0.0,
        tx_cable_loss_db: float = 0.0,
        rx_cable_loss_db: float = 0.0,
        tx_height_m: float = 0.0,
        rx_height_m: float = 0.0,
        target_fade_margin_db: float = 15.0,
        extra_path_loss_db: float = 0.0,
        actual_tx_power_dbm: Optional[float] = None,
        receiver_sensitivity_dbm: Optional[float] = None,
        __event_emitter__=None,
    ) -> str:
        """
        Plan a desired point-to-point Meshtastic link using the live local radio configuration.

        Calculates link budget, Fresnel/radio-horizon geometry and the additional
        system gain required to meet target_fade_margin_db. The maximum distance
        output is a free-space link-budget ceiling, not a real-world range forecast.
        """

        def run() -> Dict[str, Any]:
            distance = self._rf_validate_numeric("distance_km", distance_km, 0.001)
            explicit_frequency = self._rf_validate_numeric("frequency_mhz", frequency_mhz, 0.0)
            tx_gain = self._rf_validate_numeric("tx_antenna_gain_dbi", tx_antenna_gain_dbi)
            rx_gain = self._rf_validate_numeric("rx_antenna_gain_dbi", rx_antenna_gain_dbi)
            tx_loss = self._rf_validate_numeric("tx_cable_loss_db", tx_cable_loss_db, 0.0)
            rx_loss = self._rf_validate_numeric("rx_cable_loss_db", rx_cable_loss_db, 0.0)
            tx_height = self._rf_validate_numeric("tx_height_m", tx_height_m, 0.0)
            rx_height = self._rf_validate_numeric("rx_height_m", rx_height_m, 0.0)
            fade = self._rf_validate_numeric("target_fade_margin_db", target_fade_margin_db, 0.0)
            extra_loss = self._rf_validate_numeric("extra_path_loss_db", extra_path_loss_db, 0.0)

            def op(iface: TCPInterface) -> Dict[str, Any]:
                context = self._rf_context_from_iface(iface)
                warnings: List[str] = list(context.get("warnings") or [])
                frequency = explicit_frequency if explicit_frequency > 0 else self._rf_float(context.get("frequencyMHz"))
                if frequency is None or frequency <= 0:
                    raise ValueError("The live radio frequency could not be derived. Provide frequency_mhz explicitly")

                if actual_tx_power_dbm is not None:
                    tx_power = self._rf_validate_numeric("actual_tx_power_dbm", actual_tx_power_dbm)
                    tx_source = "explicit actual_tx_power_dbm"
                else:
                    tx_power = self._rf_float((context.get("tx") or {}).get("planningTxPowerDbm"))
                    if tx_power is None:
                        raise ValueError("TX power could not be derived. Provide actual_tx_power_dbm explicitly")
                    tx_source = str((context.get("tx") or {}).get("planningTxPowerSource") or "live configuration")
                    warnings.append("TX power is based on configuration/firmware limits rather than measured hardware output.")

                modem = context.get("modem") or {}
                if receiver_sensitivity_dbm is not None:
                    sensitivity = self._rf_validate_numeric("receiver_sensitivity_dbm", receiver_sensitivity_dbm)
                    sensitivity_source = "explicit receiver_sensitivity_dbm"
                else:
                    sensitivity = self._rf_receiver_sensitivity_dbm(
                        self._rf_float(modem.get("bandwidthKHz")),
                        int(modem.get("spreadingFactor")) if modem.get("spreadingFactor") else None,
                    )
                    if sensitivity is None:
                        raise ValueError("Receiver sensitivity could not be estimated. Provide receiver_sensitivity_dbm explicitly")
                    sensitivity_source = "thermal-noise estimate using 6 dB noise figure and LoRa SF SNR threshold"
                    warnings.append("Receiver sensitivity is estimated; a radio/module datasheet figure is preferable.")

                budget = self._rf_link_budget(
                    distance,
                    frequency,
                    tx_power,
                    tx_gain,
                    rx_gain,
                    tx_loss,
                    rx_loss,
                    sensitivity,
                    fade,
                    extra_loss,
                )
                budget["txPowerDbm"] = round(tx_power, 2)
                budget["txPowerSource"] = tx_source
                budget["receiverSensitivitySource"] = sensitivity_source
                budget["distanceKm"] = round(distance, 3)
                budget["frequencyMHz"] = round(frequency, 6)

                margin_after_fade = float(budget["marginAfterFadeAllowanceDb"])
                required_gain = max(0.0, -margin_after_fade)
                max_fspl = (
                    tx_power
                    + tx_gain
                    - tx_loss
                    + rx_gain
                    - rx_loss
                    - extra_loss
                    - sensitivity
                    - fade
                )
                max_distance = 10 ** ((max_fspl - 32.44 - 20.0 * math.log10(frequency)) / 20.0)

                if required_gain <= 0:
                    guidance = "The free-space link budget already meets the requested fade margin. Prioritise antenna height, Fresnel clearance, low-loss feedline and a clean installation rather than simply buying more antenna gain."
                elif required_gain <= 3:
                    guidance = "A modest net RF improvement may close the calculated gap; compare antenna gain against feedline loss and improve placement/height first."
                elif required_gain <= 6:
                    guidance = "The calculated shortfall is moderate. Consider improvements at both ends, lower-loss coax and better height/clearance rather than relying on one high-gain antenna."
                else:
                    guidance = "The calculated shortfall is large. Treat antenna gain alone as unlikely to solve it; improve path geometry, both endpoints or add a well-placed intermediate node/repeater."

                regulatory = self._rf_regulatory_assessment(context, tx_power, tx_gain, tx_loss)
                if regulatory.get("status") == "exceeds_planner_limit":
                    warnings.append("Current antenna/TX assumptions exceed the encoded regional radiated-power planning limit.")

                return {
                    "radioProfile": context,
                    "target": {"distanceKm": round(distance, 3), "targetFadeMarginDb": round(fade, 2)},
                    "linkBudget": budget,
                    "geometry": self._rf_geometry(distance, frequency, tx_height, rx_height),
                    "requiredAdditionalSystemGainDb": round(required_gain, 2),
                    "freeSpaceLinkBudgetCeilingKm": round(max_distance, 2),
                    "freeSpaceCeilingWarning": "This is only the distance implied by free-space path loss. Terrain, buildings, foliage, diffraction, antenna pattern, interference and Earth curvature can dominate real links.",
                    "purchaseGuidance": guidance,
                    "regulatoryPlanningCheck": regulatory,
                    "warnings": list(dict.fromkeys(warnings)),
                }

            return self._with_interface(op)

        return await self._run_sync(
            run,
            __event_emitter__,
            "Planning Meshtastic RF link…",
            "RF link plan complete",
        )

    async def get_config(self, section: str = "all", __event_emitter__=None) -> str:
        """
        Read local radio/module configuration. Use section='all' or a specific section such as lora, power, network, telemetry, mqtt or neighbor_info.
        Secrets are redacted according to Valves.
        """

        def run() -> Dict[str, Any]:
            requested = section.strip().lower()

            def op(iface: TCPInterface) -> Dict[str, Any]:
                local = iface.localNode
                if requested == "all":
                    return {
                        "localConfig": self._clean_data(local.localConfig),
                        "moduleConfig": self._clean_data(local.moduleConfig),
                    }
                scope, message = self._get_config_message(iface, requested)
                return {
                    "section": requested,
                    "scope": scope,
                    "config": self._clean_data(message),
                }

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Reading Meshtastic configuration…", "Configuration loaded")

    async def get_config_schema(self, section: str, __event_emitter__=None) -> str:
        """
        Describe fields, types, enum choices and current values for a configuration section.
        Call this before proposing an unfamiliar config change.
        """

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                scope, message = self._get_config_message(iface, section)
                return {
                    "section": section.strip().lower(),
                    "scope": scope,
                    "fields": self._describe_message(message),
                }

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Inspecting config schema…", "Config schema loaded")

    async def get_channels(self, include_disabled: bool = False, __event_emitter__=None) -> str:
        """Read channel configuration. Channel PSKs are redacted unless secret redaction is explicitly disabled."""

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                channels = []
                for channel in iface.localNode.channels or []:
                    try:
                        role = channel_pb2.Channel.Role.Name(channel.role)
                    except Exception:
                        role = str(channel.role)
                    if not include_disabled and role == "DISABLED":
                        continue
                    data = self._proto_to_dict(channel)
                    data["roleName"] = role
                    try:
                        data["pskDescription"] = pskToString(channel.settings.psk)
                    except Exception:
                        pass
                    channels.append(self._clean_data(data))
                return {"count": len(channels), "channels": channels}

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Reading Meshtastic channels…", "Channels loaded")

    async def get_channel_schema(self, channel_index: int = 0, __event_emitter__=None) -> str:
        """Describe writable protobuf fields and current values for one channel."""

        def run() -> Dict[str, Any]:
            if channel_index < 0 or channel_index > 7:
                raise ValueError("channel_index must be 0-7")

            def op(iface: TCPInterface) -> Dict[str, Any]:
                channels = iface.localNode.channels or []
                if channel_index >= len(channels):
                    raise ValueError(f"Channel index {channel_index} is not available")
                channel = channels[channel_index]
                return {
                    "channelIndex": channel_index,
                    "fields": self._describe_message(channel),
                }

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Inspecting channel schema…", "Channel schema loaded")

    async def get_share_url(self, include_all_channels: bool = False, __event_emitter__=None) -> str:
        """
        Return a Meshtastic channel share URL. This URL contains channel key material, so allow_secret_output must be enabled first.
        """

        def run() -> Dict[str, Any]:
            if not self.valves.allow_secret_output:
                raise PermissionError(
                    "Share URLs contain channel key material. Enable allow_secret_output in the tool Valves first."
                )

            def op(iface: TCPInterface) -> Dict[str, Any]:
                return {
                    "includeAllChannels": include_all_channels,
                    "shareUrl": iface.localNode.getURL(includeAll=include_all_channels),
                    "warning": "Treat this URL as a secret because it can contain channel encryption keys.",
                }

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Generating Meshtastic share URL…", "Share URL generated")

    # ------------------------------------------------------------------
    # Live mesh requests
    # ------------------------------------------------------------------

    async def request_telemetry(
        self,
        node: str,
        telemetry_type: str = "device_metrics",
        channel_index: int = -1,
        __event_emitter__=None,
    ) -> str:
        """
        Request fresh telemetry from another Meshtastic node and wait for its response.
        telemetry_type may be device_metrics, environment_metrics, air_quality_metrics, power_metrics or local_stats.
        """

        def run() -> Dict[str, Any]:
            telemetry_name = telemetry_type.strip().lower()
            if telemetry_name not in self.TELEMETRY_TYPES:
                raise ValueError(
                    f"Unsupported telemetry_type. Use one of: {', '.join(sorted(self.TELEMETRY_TYPES))}"
                )
            ch = self.valves.default_channel_index if channel_index < 0 else channel_index
            if ch < 0 or ch > 7:
                raise ValueError("channel_index must be 0-7")

            def op(iface: TCPInterface) -> Dict[str, Any]:
                destination = self._resolve_destination(iface, node)
                captured: Dict[str, Any] = {}

                def on_response(packet: Dict[str, Any]) -> None:
                    decoded = packet.get("decoded") or {}
                    portnum = decoded.get("portnum")
                    if portnum == "TELEMETRY_APP" or portnum == portnums_pb2.PortNum.TELEMETRY_APP:
                        telemetry = telemetry_pb2.Telemetry()
                        telemetry.ParseFromString(decoded.get("payload", b""))
                        captured["telemetry"] = self._clean_data(telemetry)
                        captured["responseFrom"] = packet.get("from")
                        captured["responseTo"] = packet.get("to")
                    else:
                        captured["responsePacket"] = self._clean_data(packet)
                    iface._acknowledgment.receivedTelemetry = True

                original = iface.onResponseTelemetry
                iface.onResponseTelemetry = on_response
                try:
                    iface.sendTelemetry(
                        destinationId=destination,
                        wantResponse=True,
                        channelIndex=ch,
                        telemetryType=telemetry_name,
                    )
                finally:
                    iface.onResponseTelemetry = original

                if "telemetry" not in captured:
                    try:
                        _, entry = self._find_node_entry(iface, str(destination))
                        captured["nodeDbAfterRequest"] = self._augment_node(entry)
                    except Exception:
                        pass
                captured["destination"] = str(destination)
                captured["telemetryType"] = telemetry_name
                return captured

            return self._with_interface(op)

        return await self._run_sync(
            run,
            __event_emitter__,
            f"Requesting {telemetry_type} telemetry…",
            "Telemetry request complete",
        )

    async def request_position(
        self,
        node: str,
        channel_index: int = -1,
        __event_emitter__=None,
    ) -> str:
        """Request a fresh position packet from another Meshtastic node and wait for the response."""

        def run() -> Dict[str, Any]:
            ch = self.valves.default_channel_index if channel_index < 0 else channel_index
            if ch < 0 or ch > 7:
                raise ValueError("channel_index must be 0-7")

            def op(iface: TCPInterface) -> Dict[str, Any]:
                destination = self._resolve_destination(iface, node)
                captured: Dict[str, Any] = {}

                def on_response(packet: Dict[str, Any]) -> None:
                    decoded = packet.get("decoded") or {}
                    portnum = decoded.get("portnum")
                    if portnum == "POSITION_APP" or portnum == portnums_pb2.PortNum.POSITION_APP:
                        position = mesh_pb2.Position()
                        position.ParseFromString(decoded.get("payload", b""))
                        captured["position"] = self._clean_data(position)
                        captured["responseFrom"] = packet.get("from")
                    else:
                        captured["responsePacket"] = self._clean_data(packet)
                    iface._acknowledgment.receivedPosition = True

                original = iface.onResponsePosition
                iface.onResponsePosition = on_response
                try:
                    iface.sendPosition(
                        destinationId=destination,
                        wantResponse=True,
                        channelIndex=ch,
                    )
                finally:
                    iface.onResponsePosition = original

                captured["destination"] = str(destination)
                return captured

            return self._with_interface(op)

        return await self._run_sync(
            run,
            __event_emitter__,
            "Requesting Meshtastic position…",
            "Position request complete",
        )

    async def traceroute(
        self,
        node: str,
        hop_limit: int = 0,
        channel_index: int = -1,
        __event_emitter__=None,
    ) -> str:
        """Run a Meshtastic traceroute to a destination and return structured route discovery data."""

        def run() -> Dict[str, Any]:
            hops = self.valves.default_traceroute_hops if hop_limit <= 0 else hop_limit
            ch = self.valves.default_channel_index if channel_index < 0 else channel_index
            if hops < 1 or hops > 7:
                raise ValueError("hop_limit must be 1-7")
            if ch < 0 or ch > 7:
                raise ValueError("channel_index must be 0-7")

            def op(iface: TCPInterface) -> Dict[str, Any]:
                destination = self._resolve_destination(iface, node)
                captured: Dict[str, Any] = {}

                def on_response(packet: Dict[str, Any]) -> None:
                    decoded = packet.get("decoded") or {}
                    payload = decoded.get("payload", b"")
                    if payload:
                        try:
                            route = mesh_pb2.RouteDiscovery()
                            route.ParseFromString(payload)
                            captured["routeDiscovery"] = self._clean_data(route)
                        except Exception:
                            pass
                    captured["responsePacket"] = self._clean_data(packet)
                    iface._acknowledgment.receivedTraceRoute = True

                route_request = mesh_pb2.RouteDiscovery()
                iface.sendData(
                    route_request,
                    destinationId=destination,
                    portNum=portnums_pb2.PortNum.TRACEROUTE_APP,
                    wantResponse=True,
                    onResponse=on_response,
                    channelIndex=ch,
                    hopLimit=hops,
                )
                node_count = len(iface.nodes or {})
                wait_factor = max(1, min(max(0, node_count - 1), hops))
                iface.waitForTraceRoute(wait_factor)
                captured["destination"] = str(destination)
                captured["hopLimit"] = hops
                captured["channelIndex"] = ch
                return captured

            return self._with_interface(op)

        return await self._run_sync(
            run,
            __event_emitter__,
            "Running Meshtastic traceroute…",
            "Traceroute complete",
        )

    async def listen_for_packets(
        self,
        seconds: int = 10,
        max_packets: int = 25,
        __event_emitter__=None,
    ) -> str:
        """
        Listen temporarily for incoming Meshtastic packets. This is not persistent message history; it only captures packets while the tool call is running.
        """

        def run() -> Dict[str, Any]:
            duration = int(seconds)
            if duration < 1 or duration > self.valves.max_listen_seconds:
                raise ValueError(
                    f"seconds must be between 1 and {self.valves.max_listen_seconds}"
                )
            if max_packets < 1 or max_packets > 200:
                raise ValueError("max_packets must be between 1 and 200")

            from pubsub import pub

            self._preflight()
            iface: Optional[TCPInterface] = None
            packets: List[Dict[str, Any]] = []

            def on_receive(packet, interface=None):
                if iface is not None and interface is not None and interface is not iface:
                    return
                if len(packets) < max_packets:
                    packets.append(self._clean_data(packet))

            try:
                iface = TCPInterface(
                    hostname=self.valves.host.strip(),
                    portNumber=int(self.valves.port),
                )
                pub.subscribe(on_receive, "meshtastic.receive")
                deadline = time.monotonic() + duration
                while time.monotonic() < deadline and len(packets) < max_packets:
                    time.sleep(0.1)
                return {
                    "listenSeconds": duration,
                    "packetCount": len(packets),
                    "packets": packets,
                }
            finally:
                try:
                    pub.unsubscribe(on_receive, "meshtastic.receive")
                except Exception:
                    pass
                if iface is not None:
                    try:
                        iface.close()
                    except Exception:
                        pass

        return await self._run_sync(
            run,
            __event_emitter__,
            f"Listening for Meshtastic packets for {seconds}s…",
            "Packet listening complete",
        )

    # ------------------------------------------------------------------
    # Messaging
    # ------------------------------------------------------------------

    async def send_message(
        self,
        message: str,
        destination: str = "^all",
        channel_index: int = -1,
        want_ack: bool = False,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """
        Send a Meshtastic text message. Requires allow_messages.
        destination can be ^all/broadcast, node ID, decimal node number, long name or short name.
        """
        if not self.valves.allow_messages:
            return self._json({"ok": False, "error": "Messaging is disabled in the tool Valves"})

        encoded = message.encode("utf-8")
        if not encoded:
            return self._json({"ok": False, "error": "Message is empty"})
        if len(encoded) > self.valves.max_message_bytes:
            return self._json(
                {
                    "ok": False,
                    "error": f"Message is {len(encoded)} UTF-8 bytes; the configured limit is {self.valves.max_message_bytes}",
                }
            )

        confirmed = await self._confirm(
            __event_call__,
            "Send Meshtastic message?",
            f"Send this message to {destination!r}:\n\n{message}",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True, "error": "Message send was not confirmed"})

        def run() -> Dict[str, Any]:
            ch = self.valves.default_channel_index if channel_index < 0 else channel_index
            if ch < 0 or ch > 7:
                raise ValueError("channel_index must be 0-7")

            def op(iface: TCPInterface) -> Dict[str, Any]:
                dest = self._resolve_destination(iface, destination)
                packet = iface.sendText(
                    message,
                    destinationId=dest,
                    wantAck=bool(want_ack),
                    channelIndex=ch,
                )
                ack = None
                if want_ack:
                    iface.waitForAckNak()
                    ack = "received"
                return {
                    "destination": str(dest),
                    "channelIndex": ch,
                    "utf8Bytes": len(encoded),
                    "ackRequested": bool(want_ack),
                    "ackStatus": ack,
                    "packet": self._clean_data(packet),
                }

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Sending Meshtastic message…", "Message sent")

    async def send_alert(
        self,
        message: str,
        destination: str = "^all",
        channel_index: int = -1,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """Send a high-priority Meshtastic alert. Requires allow_messages and allow_alerts."""
        if not self.valves.allow_messages or not self.valves.allow_alerts:
            return self._json(
                {"ok": False, "error": "High-priority alerts are disabled in the tool Valves"}
            )
        encoded = message.encode("utf-8")
        if not encoded or len(encoded) > self.valves.max_message_bytes:
            return self._json(
                {
                    "ok": False,
                    "error": f"Alert must be 1-{self.valves.max_message_bytes} UTF-8 bytes",
                }
            )

        confirmed = await self._confirm(
            __event_call__,
            "Send high-priority Meshtastic alert?",
            f"Send a HIGH-PRIORITY alert to {destination!r}:\n\n{message}",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True, "error": "Alert send was not confirmed"})

        def run() -> Dict[str, Any]:
            ch = self.valves.default_channel_index if channel_index < 0 else channel_index
            if ch < 0 or ch > 7:
                raise ValueError("channel_index must be 0-7")

            def op(iface: TCPInterface) -> Dict[str, Any]:
                dest = self._resolve_destination(iface, destination)
                packet = iface.sendAlert(message, destinationId=dest, channelIndex=ch)
                return {
                    "destination": str(dest),
                    "channelIndex": ch,
                    "packet": self._clean_data(packet),
                }

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Sending Meshtastic alert…", "Alert sent")

    # ------------------------------------------------------------------
    # Configuration changes
    # ------------------------------------------------------------------

    async def preview_config_change(
        self,
        section: str,
        field: str,
        value: str,
        __event_emitter__=None,
    ) -> str:
        """
        Validate and preview one config change without writing it. Use exact snake_case fields from get_config_schema.
        value is text/JSON, e.g. '3600', 'true', 'CLIENT_MUTE'.
        """
        return await self._run_sync(
            lambda: self._config_preview_sync(section, field, value),
            __event_emitter__,
            "Validating Meshtastic config change…",
            "Config change preview ready",
        )

    async def set_config_value(
        self,
        section: str,
        field: str,
        value: str,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """
        Apply one local config/module value after permission checks and interactive confirmation.
        Prefer preview_config_change first. Never call this merely to make a recommendation.
        """
        try:
            self._validate_write_permission(section, field)
        except Exception as exc:
            return self._json({"ok": False, "error": str(exc)})

        preview_text = await self._run_sync(
            lambda: self._config_preview_sync(section, field, value),
            None,
            "",
            "",
        )
        preview_wrapper: Dict[str, Any] = {}
        try:
            preview_wrapper = json.loads(preview_text)
            preview = preview_wrapper.get("result", {})
        except Exception:
            preview = {}

        if not preview or not preview_wrapper.get("ok"):
            return preview_text

        old_value = preview.get("oldValue")
        new_value = preview.get("newValue")
        confirmed = await self._confirm(
            __event_call__,
            "Apply Meshtastic configuration change?",
            f"Section: {section}\nField: {field}\nCurrent: {old_value}\nNew: {new_value}",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True, "error": "Configuration change was not confirmed"})

        return await self._run_sync(
            lambda: self._apply_config_sync(section, field, value),
            __event_emitter__,
            "Writing Meshtastic configuration…",
            "Configuration updated",
        )

    async def preview_config_batch(self, changes_json: str, __event_emitter__=None) -> str:
        """
        Preview multiple config changes without writing them.
        changes_json example: [{"section":"telemetry","field":"device_update_interval","value":3600}]
        """

        def run() -> Dict[str, Any]:
            changes = self._parse_batch(changes_json)

            def op(iface: TCPInterface) -> Dict[str, Any]:
                previews = []
                for change in changes:
                    scope, message = self._get_config_message(iface, change["section"])
                    proposal = self._set_proto_value(message, change["field"], change["value"])
                    proposal["section"] = change["section"].strip().lower()
                    proposal["scope"] = scope
                    previews.append(proposal)
                return {"count": len(previews), "changes": previews, "applied": False}

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Validating config batch…", "Config batch preview ready")

    async def apply_config_batch(
        self,
        changes_json: str,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """
        Apply multiple config values in one Meshtastic settings transaction with one confirmation.
        Use preview_config_batch first and only call after the user wants the changes applied.
        """
        try:
            changes = self._parse_batch(changes_json)
            for change in changes:
                self._validate_write_permission(change["section"], change["field"])
        except Exception as exc:
            return self._json({"ok": False, "error": str(exc)})

        preview_text = await self.preview_config_batch(changes_json)
        wrapper: Dict[str, Any] = {}
        try:
            wrapper = json.loads(preview_text)
            preview = wrapper.get("result", {})
        except Exception:
            preview = {}
        if not preview or not wrapper.get("ok"):
            return preview_text

        lines = []
        for change in preview.get("changes", []):
            lines.append(
                f"{change.get('section')}.{change.get('field')}: "
                f"{change.get('oldValue')} → {change.get('newValue')}"
            )
        confirmed = await self._confirm(
            __event_call__,
            "Apply Meshtastic configuration batch?",
            "Apply these changes together:\n\n" + "\n".join(lines),
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True, "error": "Configuration batch was not confirmed"})

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                # First validate/coerce every change in memory before beginning the transaction.
                applied_previews = []
                touched_sections: List[str] = []
                for change in changes:
                    section_name = change["section"].strip().lower()
                    scope, message = self._get_config_message(iface, section_name)
                    result = self._set_proto_value(message, change["field"], change["value"])
                    result["section"] = section_name
                    result["scope"] = scope
                    applied_previews.append(result)
                    if section_name not in touched_sections:
                        touched_sections.append(section_name)

                iface.localNode.beginSettingsTransaction()
                for section_name in touched_sections:
                    iface.localNode.writeConfig(section_name)
                iface.localNode.commitSettingsTransaction()
                time.sleep(0.3)
                return {
                    "count": len(applied_previews),
                    "sectionsWritten": touched_sections,
                    "changes": applied_previews,
                    "applied": True,
                    "usedSettingsTransaction": True,
                }

            return self._with_interface(op)

        return await self._run_sync(
            run,
            __event_emitter__,
            "Applying Meshtastic config transaction…",
            "Configuration batch applied",
        )

    async def set_node_name(
        self,
        long_name: str,
        short_name: str,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """Set the local Meshtastic owner long/short name. Requires allow_config_writes."""
        if not self.valves.allow_config_writes:
            return self._json({"ok": False, "error": "Configuration writes are disabled"})
        if not long_name.strip():
            return self._json({"ok": False, "error": "long_name cannot be empty"})
        if not short_name.strip():
            return self._json({"ok": False, "error": "short_name cannot be empty"})

        confirmed = await self._confirm(
            __event_call__,
            "Rename Meshtastic node?",
            f"Set owner name to {long_name!r} and short name to {short_name[:4]!r}?",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True})

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                iface.localNode.setOwner(long_name=long_name, short_name=short_name)
                time.sleep(0.2)
                return {"longName": long_name.strip(), "shortName": short_name.strip()[:4]}

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Renaming Meshtastic node…", "Node renamed")

    # ------------------------------------------------------------------
    # Channel administration
    # ------------------------------------------------------------------

    async def set_channel_value(
        self,
        channel_index: int,
        field: str,
        value: str,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """
        Set one channel protobuf field, e.g. settings.name, settings.uplink_enabled, settings.downlink_enabled or role.
        PSK changes require allow_sensitive_config_writes; prefer set_channel_psk for keys.
        """
        if not self.valves.allow_channel_writes:
            return self._json({"ok": False, "error": "Channel writes are disabled"})
        if channel_index < 0 or channel_index > 7:
            return self._json({"ok": False, "error": "channel_index must be 0-7"})
        if self._is_sensitive_key(field) and not self.valves.allow_sensitive_config_writes:
            return self._json({"ok": False, "error": "Sensitive channel writes are disabled"})

        def preview_sync() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                channels = iface.localNode.channels or []
                if channel_index >= len(channels):
                    raise ValueError(f"Channel index {channel_index} is not available")
                change = self._set_proto_value(channels[channel_index], field, value)
                return {"channelIndex": channel_index, **change, "applied": False}

            return self._with_interface(op)

        preview_text = await self._run_sync(preview_sync)
        wrapper = json.loads(preview_text)
        if not wrapper.get("ok"):
            return preview_text
        preview = wrapper["result"]
        confirmed = await self._confirm(
            __event_call__,
            "Change Meshtastic channel?",
            f"Channel {channel_index}\nField: {field}\nCurrent: {preview.get('oldValue')}\nNew: {preview.get('newValue')}",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True})

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                channels = iface.localNode.channels or []
                if channel_index >= len(channels):
                    raise ValueError(f"Channel index {channel_index} is not available")
                change = self._set_proto_value(channels[channel_index], field, value)
                iface.localNode.writeChannel(channel_index)
                time.sleep(0.2)
                return {"channelIndex": channel_index, **change, "applied": True}

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Writing channel settings…", "Channel updated")

    async def set_channel_psk(
        self,
        channel_index: int,
        psk: str,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """
        Set a channel PSK. Requires allow_channel_writes and allow_sensitive_config_writes.
        psk accepts Meshtastic forms such as default, random, none, simpleN, 0xHEX or base64:DATA.
        """
        if not self.valves.allow_channel_writes or not self.valves.allow_sensitive_config_writes:
            return self._json({"ok": False, "error": "Sensitive channel writes are disabled"})
        if channel_index < 0 or channel_index > 7:
            return self._json({"ok": False, "error": "channel_index must be 0-7"})
        try:
            new_psk = fromPSK(psk)
            description = pskToString(new_psk)
        except Exception as exc:
            return self._json({"ok": False, "error": f"Invalid PSK: {exc}"})

        confirmed = await self._confirm(
            __event_call__,
            "Change Meshtastic channel encryption key?",
            f"Replace the PSK for channel {channel_index}? New key type: {description}. Existing devices may lose access if their key is not updated.",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True})

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                channels = iface.localNode.channels or []
                if channel_index >= len(channels):
                    raise ValueError(f"Channel index {channel_index} is not available")
                before = pskToString(channels[channel_index].settings.psk)
                channels[channel_index].settings.psk = new_psk
                iface.localNode.writeChannel(channel_index)
                time.sleep(0.2)
                return {
                    "channelIndex": channel_index,
                    "oldPskType": before,
                    "newPskType": description,
                    "pskValue": "[REDACTED_SECRET]",
                    "applied": True,
                }

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Updating channel PSK…", "Channel PSK updated")

    async def delete_channel(
        self,
        channel_index: int,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """Delete a secondary Meshtastic channel and shift later channels up. Requires allow_channel_writes."""
        if not self.valves.allow_channel_writes:
            return self._json({"ok": False, "error": "Channel writes are disabled"})
        if channel_index <= 0 or channel_index > 7:
            return self._json({"ok": False, "error": "Only secondary channel indexes 1-7 may be deleted"})

        confirmed = await self._confirm(
            __event_call__,
            "Delete Meshtastic channel?",
            f"Delete secondary channel index {channel_index}? Later channels may be shifted to new indexes.",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True})

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                iface.localNode.deleteChannel(channel_index)
                time.sleep(0.3)
                return {"deletedChannelIndex": channel_index, "applied": True}

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Deleting Meshtastic channel…", "Channel deleted")

    async def import_channel_url(
        self,
        share_url: str,
        add_only: bool = True,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """
        Import a Meshtastic share URL. add_only=True adds missing channels; False replaces channel configuration.
        Requires channel/config/sensitive write permissions because share URLs contain key material.
        """
        if not (
            self.valves.allow_channel_writes
            and self.valves.allow_config_writes
            and self.valves.allow_sensitive_config_writes
        ):
            return self._json(
                {
                    "ok": False,
                    "error": "Importing a channel URL requires allow_channel_writes, allow_config_writes and allow_sensitive_config_writes",
                }
            )
        if not share_url.strip():
            return self._json({"ok": False, "error": "share_url is empty"})

        confirmed = await self._confirm(
            __event_call__,
            "Import Meshtastic channel URL?",
            "Import the supplied channel share URL? "
            + ("Existing channels will be preserved where possible." if add_only else "This can replace existing channel/radio settings."),
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True})

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                iface.localNode.setURL(share_url.strip(), addOnly=bool(add_only))
                time.sleep(0.4)
                return {
                    "imported": True,
                    "addOnly": bool(add_only),
                    "shareUrl": "[REDACTED_SECRET]",
                }

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Importing channel configuration…", "Channel configuration imported")

    # ------------------------------------------------------------------
    # NodeDB administration
    # ------------------------------------------------------------------

    async def set_node_favorite(
        self,
        node: str,
        favorite: bool = True,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """Set or clear the favourite flag for a node in the local NodeDB. Requires allow_nodedb_writes."""
        if not self.valves.allow_nodedb_writes:
            return self._json({"ok": False, "error": "NodeDB writes are disabled"})
        confirmed = await self._confirm(
            __event_call__,
            "Change NodeDB favourite?",
            f"{'Favourite' if favorite else 'Unfavourite'} node {node!r}?",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True})

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                key, entry = self._find_node_entry(iface, node)
                node_id = (entry.get("user") or {}).get("id") or key
                if favorite:
                    iface.localNode.setFavorite(node_id)
                else:
                    iface.localNode.removeFavorite(node_id)
                time.sleep(0.2)
                return {"node": node_id, "favorite": bool(favorite)}

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Updating NodeDB favourite…", "NodeDB favourite updated")

    async def set_node_ignored(
        self,
        node: str,
        ignored: bool = True,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """Set or clear the ignored flag for a node in the local NodeDB. Requires allow_nodedb_writes."""
        if not self.valves.allow_nodedb_writes:
            return self._json({"ok": False, "error": "NodeDB writes are disabled"})
        confirmed = await self._confirm(
            __event_call__,
            "Change NodeDB ignored state?",
            f"{'Ignore' if ignored else 'Stop ignoring'} node {node!r}?",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True})

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                key, entry = self._find_node_entry(iface, node)
                node_id = (entry.get("user") or {}).get("id") or key
                if ignored:
                    iface.localNode.setIgnored(node_id)
                else:
                    iface.localNode.removeIgnored(node_id)
                time.sleep(0.2)
                return {"node": node_id, "ignored": bool(ignored)}

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Updating ignored node state…", "Ignored state updated")

    async def remove_node_from_database(
        self,
        node: str,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """Remove one node from the local Meshtastic NodeDB. Requires allow_nodedb_writes."""
        if not self.valves.allow_nodedb_writes:
            return self._json({"ok": False, "error": "NodeDB writes are disabled"})
        confirmed = await self._confirm(
            __event_call__,
            "Remove Meshtastic node from NodeDB?",
            f"Remove {node!r} from this device's local NodeDB? It may reappear if heard again.",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True})

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                key, entry = self._find_node_entry(iface, node)
                node_id = (entry.get("user") or {}).get("id") or key
                iface.localNode.removeNode(node_id)
                time.sleep(0.2)
                return {"removedNode": node_id}

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Removing node from NodeDB…", "Node removed from NodeDB")

    async def reset_node_database(self, __event_call__=None, __event_emitter__=None) -> str:
        """Clear the entire local Meshtastic NodeDB. Requires allow_nodedb_writes and interactive confirmation."""
        if not self.valves.allow_nodedb_writes:
            return self._json({"ok": False, "error": "NodeDB writes are disabled"})
        confirmed = await self._confirm(
            __event_call__,
            "Clear entire Meshtastic NodeDB?",
            "This will clear every learned node from the local device NodeDB. Nodes can repopulate as they are heard again.",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True})

        return await self._run_sync(
            lambda: self._with_interface(lambda iface: (iface.localNode.resetNodeDb(), {"reset": True})[1]),
            __event_emitter__,
            "Resetting Meshtastic NodeDB…",
            "NodeDB reset requested",
        )

    # ------------------------------------------------------------------
    # Position and device administration
    # ------------------------------------------------------------------

    async def set_fixed_position(
        self,
        latitude: float,
        longitude: float,
        altitude_m: int = 0,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """Set the local node's fixed GPS position. Requires allow_position_writes."""
        if not self.valves.allow_position_writes:
            return self._json({"ok": False, "error": "Position writes are disabled"})
        if latitude < -90 or latitude > 90 or longitude < -180 or longitude > 180:
            return self._json({"ok": False, "error": "Latitude/longitude are outside valid ranges"})

        display_position = (
            "[REDACTED_POSITION]"
            if self.valves.redact_positions
            else f"{latitude:.7f}, {longitude:.7f}, altitude {altitude_m} m"
        )
        confirmed = await self._confirm(
            __event_call__,
            "Set fixed Meshtastic position?",
            f"Set the local node's fixed position to {display_position}?",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True})

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                iface.localNode.setFixedPosition(latitude, longitude, altitude_m)
                time.sleep(0.2)
                return self._clean_data(
                    {
                        "latitude": latitude,
                        "longitude": longitude,
                        "altitude": altitude_m,
                        "fixedPosition": True,
                    }
                )

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Setting fixed Meshtastic position…", "Fixed position updated")

    async def remove_fixed_position(self, __event_call__=None, __event_emitter__=None) -> str:
        """Remove the local node's fixed position setting. Requires allow_position_writes."""
        if not self.valves.allow_position_writes:
            return self._json({"ok": False, "error": "Position writes are disabled"})
        confirmed = await self._confirm(
            __event_call__,
            "Remove fixed Meshtastic position?",
            "Remove the local node's configured fixed position?",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True})

        return await self._run_sync(
            lambda: self._with_interface(lambda iface: (iface.localNode.removeFixedPosition(), {"fixedPosition": False})[1]),
            __event_emitter__,
            "Removing fixed Meshtastic position…",
            "Fixed position removed",
        )

    async def sync_device_time(self, __event_call__=None, __event_emitter__=None) -> str:
        """Set the local Meshtastic node clock to the Open WebUI server's current Unix time. Requires allow_admin_actions."""
        if not self.valves.allow_admin_actions:
            return self._json({"ok": False, "error": "Administrative actions are disabled"})
        now = int(time.time())
        confirmed = await self._confirm(
            __event_call__,
            "Synchronise Meshtastic clock?",
            f"Set the device clock to {self._timestamp_iso(now)} based on the Open WebUI server time?",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True})

        def run() -> Dict[str, Any]:
            def op(iface: TCPInterface) -> Dict[str, Any]:
                iface.localNode.setTime(now)
                time.sleep(0.2)
                return {"unixTime": now, "utc": self._timestamp_iso(now)}

            return self._with_interface(op)

        return await self._run_sync(run, __event_emitter__, "Synchronising Meshtastic clock…", "Clock synchronised")

    async def reboot_device(
        self,
        delay_seconds: int = 5,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """Reboot the local Meshtastic device after a short delay. Requires allow_admin_actions."""
        if not self.valves.allow_admin_actions:
            return self._json({"ok": False, "error": "Administrative actions are disabled"})
        if delay_seconds < 1 or delay_seconds > 60:
            return self._json({"ok": False, "error": "delay_seconds must be between 1 and 60"})
        confirmed = await self._confirm(
            __event_call__,
            "Reboot Meshtastic device?",
            f"Reboot the local Meshtastic node in {delay_seconds} seconds? It will briefly disappear from Wi-Fi.",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True})

        return await self._run_sync(
            lambda: self._with_interface(lambda iface: (iface.localNode.reboot(delay_seconds), {"rebootScheduledInSeconds": delay_seconds})[1]),
            __event_emitter__,
            "Scheduling Meshtastic reboot…",
            "Reboot scheduled",
        )

    async def shutdown_device(
        self,
        delay_seconds: int = 5,
        __event_call__=None,
        __event_emitter__=None,
    ) -> str:
        """Shut down the local Meshtastic device after a short delay. Requires allow_admin_actions."""
        if not self.valves.allow_admin_actions:
            return self._json({"ok": False, "error": "Administrative actions are disabled"})
        if delay_seconds < 1 or delay_seconds > 60:
            return self._json({"ok": False, "error": "delay_seconds must be between 1 and 60"})
        confirmed = await self._confirm(
            __event_call__,
            "Shut down Meshtastic device?",
            f"Shut down the local Meshtastic node in {delay_seconds} seconds? Physical intervention/power cycling may be needed to bring it back.",
        )
        if not confirmed:
            return self._json({"ok": False, "cancelled": True})

        return await self._run_sync(
            lambda: self._with_interface(lambda iface: (iface.localNode.shutdown(delay_seconds), {"shutdownScheduledInSeconds": delay_seconds})[1]),
            __event_emitter__,
            "Scheduling Meshtastic shutdown…",
            "Shutdown scheduled",
        )

    # Deliberately NOT exposed to the LLM:
    # - factoryReset()
    # - rebootOTA()
    # - enterDFUMode()
    # These are recoverability-impacting operations and are better kept outside a
    # conversational tool even when other administration features are enabled.
