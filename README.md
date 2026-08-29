<!-- PROJECT SHIELDS -->
[![GPLv3 License][license-shield]][license-url]
[![Meshtastic][meshtastic-shield]][meshtastic-url]
[![Open WebUI][openwebui-shield]][openwebui-url]
[![Python][python-shield]][python-url]
[![Downloads][downloads-shield]][openwebui-tool-url]
[![Reddit][reddit-shield]][reddit-url]

<br />
<div align="center">
    <img src="https://meshtastic.org/img/logo.svg" alt="Meshtastic" height="100">
    &nbsp;&nbsp;&nbsp;&nbsp;
    <img src="https://docs.openwebui.com/assets/files/open-webui-logo-a5024b13d950315f75cf406700bbd404.png" style="border-radius: 12.5px;" alt="Open WebUI" height="100">

  <h3>Meshtastic - Conversational Mesh Diagnostics &amp; RF Planning for Open WebUI</h3>

  <p>
    An Open WebUI Workspace Tool that gives an LLM direct, safe access to a Meshtastic node over Wi-Fi/TCP.
    Ask your local model how your mesh is doing, run traceroutes, inspect telemetry, manage configuration,
    and plan RF links - all conversationally.
    <br />
    <a href="https://github.com/beecho01/open-webui-tool-meshtastic"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://openwebui.com/posts/d61541f8-9291-4d30-830a-77aff6b03add">Open WebUI Post</a>
    &middot;
    <a href="https://www.reddit.com/r/meshtastic/comments/1vp70wf/openwebui_meshtastic_tool/">Reddit Thread</a>
    &middot;
    <a href="https://github.com/beecho01/open-webui-tool-meshtastic/issues/new?labels=bug&template=bug-report.md">Report Bug</a>
    &middot;
    <a href="https://github.com/beecho01/open-webui-tool-meshtastic/issues/new?labels=enhancement&template=feature-request.md">Request Feature</a>
  </p>
</div>

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#about-the-project">About The Project</a></li>
    <li><a href="#key-features">Key Features</a></li>
    <li><a href="#safety--permissions">Safety &amp; Permissions</a></li>
    <li><a href="#built-with">Built With</a></li>
    <li><a href="#getting-started">Getting Started</a></li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#rf-planning">RF Planning</a></li>
    <li><a href="#terrain--elevation-data">Terrain &amp; Elevation Data</a></li>
    <li><a href="#valves-reference">Valves Reference</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#links">Links</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
    <li><a href="#changelog">Changelog</a></li>
  </ol>
</details>

---

## About The Project

The original idea was simply: **"Wouldn't it be cool if I could ask my local LLM what my Meshtastic network is doing?"**

This Open WebUI Workspace Tool connects to a Meshtastic device over its TCP interface and lets you interact with it conversationally. You can ask things like:

- *"How healthy does my mesh look?"*
- *"Which nodes have the weakest SNR?"*
- *"Run a traceroute to X Node"*
- *"Explain my current LoRa configuration."*
- *"Compare these two antennas for my node."*
- *"What's the link budget to the node 5 km away?"*

It can request telemetry, inspect the NodeDB, manage channels and configuration, send messages, and perform basic device administration. It's now becoming something closer to a **conversational diagnostics and RF-planning assistant** for Meshtastic.

<p align="right">(<a href="#top">back to top</a>)</p>

## Key Features

### Diagnostics & Inspection (read-only by default)

- **Connection test**: TCP and Meshtastic protocol reachability check with metadata
- **Device summary**: firmware/hardware, owner, telemetry, radio settings and NodeDB count at a glance
- **NodeDB browsing**: list, search and inspect individual nodes with full metadata
- **Mesh health**: SNR statistics, hop distribution, low-battery peers, weakest-signal nodes, MQTT vs RF observations
- **Telemetry requests**: on-demand device, environment, air-quality, power and local-stats telemetry from any node
- **Position requests**: request a position update from a node
- **Traceroute**: run a Meshtastic traceroute and get structured route-discovery data
- **Packet listener**: temporarily capture live packets for a configurable duration
- **Configuration inspection**: read any local or module config section with schema support
- **Channel inspection**: list channels, inspect channel schema, generate share URLs

### Messaging (opt-in)

- **Send text messages**: broadcast or direct, with acknowledgement support
- **Send high-priority alerts**: separately gated alert messaging

### Configuration Management (opt-in)

- **Preview before writing**: validate a single change or a batch without touching the radio
- **Apply config changes**: single field or batch JSON, with interactive confirmation
- **Channel management**: set channel values, PSKs, delete channels, import from share URL
- **NodeDB management**: favourite, ignore, remove nodes, reset the NodeDB
- **Position management**: set or remove a fixed device position
- **Device administration**: sync clock, reboot, shutdown (factory reset / DFU deliberately excluded)

### RF Planning (new in v0.4.1)

- **Link analysis**: link budget, Fresnel clearance, radio horizon using live LoRa settings
- **Link planning**: target a distance and get the additional system gain required
- **Antenna comparison**: compare candidate antenna systems with cable loss and regulatory checks
- **Whole-mesh RF analysis**: rank positioned peers, estimate free-space margins, build a calibration set from direct SNR observations
- **Regulatory awareness**: encoded region table with power/duty/spacing limits for planning checks
- **Modem preset awareness**: documented link budgets and live SF/bandwidth/CR mapping

<p align="right">(<a href="#top">back to top</a>)</p>

## Safety & Permissions

Safety is a major part of the design. The tool is **read-only by default**.

| Permission Valve | Default | Controls |
|---|---|---|
| `allow_messages` | `False` | Sending text messages |
| `allow_alerts` | `False` | High-priority alert messages |
| `allow_config_writes` | `False` | Local device/module config writes |
| `allow_channel_writes` | `False` | Channel changes, deletion, import |
| `allow_sensitive_config_writes` | `False` | PSKs, private keys, passwords |
| `allow_region_changes` | `False` | LoRa region changes (regulatory) |
| `allow_position_writes` | `False` | Setting/removing fixed position |
| `allow_nodedb_writes` | `False` | Favourite/ignore/remove/reset NodeDB |
| `allow_admin_actions` | `False` | Reboot, shutdown, clock sync |
| `confirm_mutations` | `True` | Interactive Open WebUI confirmation before any write |
| `redact_secrets` | `True` | PSKs/passwords/keys redacted from output |
| `redact_positions` | `False` | Lat/lon redacted from LLM output |
| `allow_secret_output` | `False` | Allow outputs containing channel secrets (e.g. share URLs) |

Additional safety notes:

- **Factory reset, rebootOTA and DFU mode are deliberately not exposed** to the LLM, even when admin actions are enabled.
- **External terrain lookups are separately opt-in** because they disclose endpoint coordinates to the configured elevation service.
- **Secrets are redacted by default**: PSKs, passwords, private keys and similar are masked before reaching the model.

<p align="right">(<a href="#top">back to top</a>)</p>

## Built With

- [Meshtastic Python SDK](https://github.com/meshtastic/python) - `meshtastic==2.7.11`
- [Open WebUI](https://open-webui.com/) - Workspace Tools framework
- [Pydantic](https://docs.pydantic.dev/) - Valves validation
- [Protocol Buffers](https://protobuf.dev/) - Meshtastic mesh/channel/telemetry protos
- [OpenTopoData](https://www.opentopodata.org/) - optional terrain elevation API

<p align="right">(<a href="#top">back to top</a>)</p>

## Getting Started

### Prerequisites

1. A running [Open WebUI](https://open-webui.com/) instance
2. A Meshtastic node reachable from the Open WebUI server over TCP/Wi-Fi (normally port **4403**)
3. The Meshtastic Python package installed in the Open WebUI environment:

   ```bash
   pip install meshtastic==2.7.11
   ```

### Installation

1. Download the latest release from the [releases folder](releases/) or the [releases page](https://github.com/beecho01/open-webui-tool-meshtastic/releases)

2. In Open WebUI, navigate to **Workspace → Tools**

3. Click **Import Tool** and select the downloaded `.py` file (e.g. `meshtastic_0.4.1.py`)

4. Open the tool's **Valves** and set your Meshtastic device's IP or hostname:

   | Valve | Example | Description |
   |---|---|---|
   | `host` | `192.168.1.60` | IP address or hostname of your Meshtastic node |
   | `port` | `4403` | Meshtastic TCP port (standard is 4403) |

5. Enable the tool for your model and start asking questions

<p align="right">(<a href="#top">back to top</a>)</p>

## Usage

Once installed and enabled, just talk to your model naturally. Here are some examples:

### Mesh Diagnostics

```
How healthy does my mesh look right now?
```

```
Which nodes have the weakest SNR in the last hour?
```

```
Show me a summary of my device - firmware, radio settings, channels.
```

### Traceroute & Telemetry

```
Run a traceroute to !a1b2c3d4
```

```
Request telemetry from the node called "Garden Sensor"
```

### Configuration

```
Explain my current LoRa configuration.
```

```
What's my current modem preset and what does it mean?
```

### Messaging

> Requires `allow_messages` enabled in Valves

```
Send "Hello from the LLM!" to the node called "Repeater"
```

### RF Planning

```
Analyse the RF link to the node called "Hilltop Repeater"
```

```
Compare these antennas: 5.8 dBi omni with 1.2 dB cable loss vs 3 dBi omni with 0.5 dB cable loss
```

```
Plan a 5 km link at my current LoRa settings - what additional gain do I need?
```

```
Analyse my whole mesh for interesting RF paths
```

<p align="right">(<a href="#top">back to top</a>)</p>

## RF Planning

The RF planning features (introduced in v0.4.1) let the model use the node's **live LoRa settings** to perform engineering calculations:

- **Link budgets**: free-space path loss, received power, fade margin
- **Fresnel clearance**: zone obstruction analysis for given antenna heights
- **Radio horizon**: Earth-curvature-limited line-of-sight distance
- **Antenna comparison**: net RF improvement, EIRP/ERP, regulatory planning checks
- **Whole-mesh analysis**: distance/bearing to all positioned peers, calibration from direct SNR observations
- **Regulatory awareness**: encoded region table (power, duty cycle, channel spacing) for planning checks

### Important disclaimers

- All RF calculations are **free-space planning estimates**, not real-world range forecasts
- TX power is derived from **configuration/firmware limits**, not measured hardware output
- Receiver sensitivity is **estimated** from thermal noise unless you provide a datasheet figure
- Terrain, buildings, foliage, diffraction, antenna pattern and interference can dominate real links
- The encoded regulatory data is for **planning only**: local law and the radio hardware's actual PA limit always take precedence

<p align="right">(<a href="#top">back to top</a>)</p>

## Terrain & Elevation Data

RF tools can optionally use **terrain elevation data** to help identify obstructions between positioned nodes.

- **Off by default**: enable `rf_allow_external_terrain_requests` in Valves
- Uses an [OpenTopoData](https://www.opentopodata.org/)-compatible API
- **Privacy note**: enabling this sends endpoint coordinates to the configured elevation service
- **Self-hosting**: point `rf_terrain_api_base` at your own OpenTopoData server and set `rf_terrain_self_hosted=True` for higher sample limits
- Public OpenTopoData is capped at 100 samples per request; self-hosted mode can use more

<p align="right">(<a href="#top">back to top</a>)</p>

## Valves Reference

### Connection

| Valve | Default | Description |
|---|---|---|
| `host` | `192.168.1.60` | Meshtastic device IP/hostname |
| `port` | `4403` | TCP port |
| `connect_timeout_seconds` | `5.0` | TCP reachability pre-check timeout |
| `default_channel_index` | `0` | Default channel for messaging/requests |
| `default_traceroute_hops` | `3` | Default hop limit for traceroute |
| `max_message_bytes` | `200` | Max UTF-8 message size |
| `max_listen_seconds` | `30` | Max duration for packet listener |

### RF Installation Profile (optional)

| Valve | Default | Description |
|---|---|---|
| `rf_use_local_installation_profile` | `False` | Use local antenna/cable/height defaults |
| `rf_local_antenna_gain_dbi` | `0.0` | Local antenna gain |
| `rf_local_cable_loss_db` | `0.0` | Local feedline/connector loss |
| `rf_local_antenna_height_m_agl` | `0.0` | Local antenna height above ground |
| `rf_local_ground_elevation_m_asl` | `-9999` | Known local ground elevation (unknown = -9999) |
| `rf_local_measured_tx_power_dbm` | `-9999` | Measured conducted TX power (unknown = -9999) |
| `rf_remote_profiles_json` | `{}` | JSON object of known remote node RF data |

### Terrain (opt-in)

| Valve | Default | Description |
|---|---|---|
| `rf_allow_external_terrain_requests` | `False` | Allow terrain API calls |
| `rf_terrain_api_base` | `https://api.opentopodata.org` | Elevation API URL |
| `rf_terrain_dataset` | `srtm30m,mapzen,etopo1` | Dataset stack |
| `rf_terrain_self_hosted` | `False` | Treat API as self-hosted |
| `rf_terrain_sampling_mode` | `adaptive` | `adaptive` or `fixed` |
| `rf_terrain_target_spacing_m` | `25.0` | Target sample spacing (adaptive) |
| `rf_terrain_max_samples` | `2000` | Max samples (self-hosted) |
| `rf_earth_k_factor` | `1.333` | Effective Earth radius factor |

### Safety & Permissions

See the [Safety & Permissions](#safety--permissions) table above.

<p align="right">(<a href="#top">back to top</a>)</p>

## Roadmap

- [ ] Add support for newer Meshtastic Python SDK versions
- [ ] Additional RF analysis (interference modelling, multi-hop path planning)
- [ ] Graph/visualisation outputs for mesh health
- [ ] Persistent message history capture
- [ ] Channel import/export workflows
- [ ] Additional hardware model hints for RF planning

See the [open issues](https://github.com/beecho01/open-webui-tool-meshtastic/issues) for a full list of proposed features and known issues.

<p align="right">(<a href="#top">back to top</a>)</p>

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the "enhancement" tag.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

<p align="right">(<a href="#top">back to top</a>)</p>

## License

Distributed under the **GPLv3 License**. See `LICENSE` for more information.

<p align="right">(<a href="#top">back to top</a>)</p>

## Links

 - James Beeching - [@beecho01](https://github.com/beecho01)
 - Project Link: [https://github.com/beecho01/open-webui-tool-meshtastic](https://github.com/beecho01/open-webui-tool-meshtastic)
 - Open WebUI Post: [https://openwebui.com/posts/d61541f8-9291-4d30-830a-77aff6b03add](https://openwebui.com/posts/d61541f8-9291-4d30-830a-77aff6b03add)

<p align="right">(<a href="#top">back to top</a>)</p>

## Acknowledgments

- [Meshtastic](https://meshtastic.org/) - the open-source mesh networking project this tool supports
- [Meshtastic Python SDK](https://github.com/meshtastic/python) - the underlying library
- [Open WebUI](https://open-webui.com/) - the platform that makes conversational tool use possible
- [OpenTopoData](https://www.opentopodata.org/) - free and self-hostable elevation API
- [Best-README-Template](https://github.com/othneildrew/Best-README-Template) - README structure inspiration
- [Choose an Open Source License](https://choosealicense.com/)
- [Img Shields](https://shields.io/)

<p align="right">(<a href="#top">back to top</a>)</p>

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
[license-shield]: https://img.shields.io/badge/license-GPLv3-blue.svg
[license-url]: https://github.com/beecho01/open-webui-tool-meshtastic/blob/main/LICENSE
[meshtastic-shield]: https://img.shields.io/badge/Meshtastic-2.7.11-green.svg
[meshtastic-url]: https://meshtastic.org/
[openwebui-shield]: https://img.shields.io/badge/Open%20WebUI-Tool-orange.svg
[openwebui-url]: https://open-webui.com/
[python-shield]: https://img.shields.io/badge/Python-3.10+-blue.svg
[python-url]: https://www.python.org/
[downloads-shield]: https://img.shields.io/badge/Open%20WebUI-Download-brightgreen.svg
[openwebui-tool-url]: https://openwebui.com/posts/d61541f8-9291-4d30-830a-77aff6b03add
[reddit-shield]: https://img.shields.io/badge/Reddit-r%2Fmeshtastic-FF4500.svg
[reddit-url]: https://www.reddit.com/r/meshtastic/comments/1vp70wf/openwebui_meshtastic_tool/
