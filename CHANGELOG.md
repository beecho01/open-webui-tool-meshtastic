# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.8] — 2026-09-04

### Changed
- **Topology diagram legend restyled** — the floating overlay legend is now a bottom-anchored bar with flex-wrap layout, using theme-aware CSS variables for consistent contrast in both light and dark modes
- **Node dragging disabled** in the topology diagram (`dragNodes: false`) so ring position always reflects hop count at a glance; pan and zoom remain interactive
- Ring guide lines use solid strokes with increased opacity for better visibility

### Fixed
- Ring spacing calculation corrected so all hop-count rings use consistent `ring_spacing * (ring + 1)` geometry


---


## [0.5.7] — 2026-09-03

### Added
- **Live theme detection** for the topology diagram — the embed now follows Open WebUI's theme (dark/light/OLED) in real time via `MutationObserver`, `matchMedia`, and `storage` events, falling back to OS `prefers-color-scheme` when the iframe cannot read the parent
- **`applyMeshTheme` function** — theme changes dynamically update node font colours and redraw the network without reloading the diagram

### Changed
- Ring guide lines use solid strokes with higher opacity (`0.16`/`0.14`) instead of dashed lines
- Theme script and chrome-strip CSS injected into `<head>` for proper load ordering


---


## [0.5.6] — 2026-09-02

### Added
- **Theme-aware topology diagram** — the vis.js embed now detects and follows the Open WebUI theme (dark/light/OLED) via parent DOM inspection, `localStorage`, and `prefers-color-scheme` fallback
- **CSS variable theming** — diagram background, font colour, legend background, border, and muted text all use `--mesh-*` CSS custom properties with light-mode overrides
- Node font colours updated dynamically on initial render based on detected theme

### Changed
- Bootstrap card chrome stripping now uses theme-aware CSS variables instead of hardcoded dark colours
- Legend uses theme-aware `var(--mesh-*)` colours instead of hardcoded values


---


## [0.5.5] — 2026-09-01

### Added
- **Inline Open WebUI embed delivery** — `get_mesh_topology` now returns `(HTMLResponse, result_payload)` instead of emitting HTML via `__event_emitter__` message events, so the interactive diagram is rendered as a sandboxed, script-enabled iframe (`message.embeds`) that survives message-content overwrite at response completion and persists across chat reloads
- **Concentric ring guides** — hop-count rings are now drawn as dashed canvas circles behind the network via a `beforeDrawing` hook, making the hop geometry visually explicit
- **Bootstrap chrome stripping** — pyvis's card/frame wrapper CSS is overridden so the diagram fills the embed iframe edge-to-edge
- **Floating legend overlay** — a positioned legend showing node count, measured link count, SNR colour key, and ring meaning
- `starlette` added to imports for `HTMLResponse`

### Changed
- `get_mesh_topology` return type annotation changed from `str` to `Any` to reflect the tuple return
- Tool docstring updated to explain the embed delivery model and that the model should describe the mesh from the JSON summary rather than reproducing the diagram


---


## [0.5.0] — 2026-08-29

### Added
- **Mesh topology diagram** — `get_mesh_topology` builds a NetworkX graph from live NodeDB data and renders it as an interactive vis.js diagram pushed directly into the chat:
  - Edge thickness and colour reflect measured SNR (green/amber/red)
  - Nodes laid out in rings by hop count, centred on the local node
  - Only `hopsAway == 0` peers get a real "measured" edge; multi-hop peers are shown with a clearly-labelled dashed "path unknown" edge rather than an invented link, since a single node's NodeDB cannot reveal the actual relay path (use `traceroute` for that)
  - Diagram stays pan/zoom/drag/hover interactive in the rendered preview
  - Does not use node position/lat-lon; layout is relative hop geometry only
- `topology_max_nodes` Valve — caps how many NodeDB peers are included in the diagram
- `topology_render_interactive` Valve — toggle the interactive diagram on/off independently of the JSON summary
- `topology_vis_js_source` Valve — `remote` (small, CDN-loaded) or `in_line` (fully self-contained, ~700 KB) vis-network delivery

### Changed
- `get_tool_info` now reports mesh topology capability gates

---

## [0.4.1] — 2026-08-29

### Added
- **RF planning suite** — the model can now use the node's live LoRa settings for engineering analysis:
  - `rf_analyse_link` — link budget, Fresnel clearance, radio horizon with optional terrain profiling
  - `rf_plan_link` — target a distance and get the additional system gain required
  - `rf_compare_antennas` — compare candidate antenna systems with cable loss and regulatory checks
  - `rf_analyse_mesh` — whole-mesh RF analysis: rank positioned peers, estimate free-space margins, build calibration set from direct SNR observations
- **Encoded regulatory region table** — power, duty cycle, channel spacing and radiated-power limits for planning checks, mirroring the Meshtastic firmware region table as of 2026-08-22
- **Modem preset awareness** — documented link budgets and live SF/bandwidth/CR mapping for all current Meshtastic presets
- **Optional terrain elevation** — OpenTopoData-compatible API integration with adaptive/fixed sampling, self-hosted mode, and public 100-sample cap
- **Optional local RF installation profile** — antenna gain, cable loss, height, ground elevation and measured TX power as Valves defaults
- **Optional remote node RF profiles** — JSON object of known remote node RF data for whole-mesh analysis
- **Hardware model hints** — conservative published family capability data for supported hardware models
- `rf_allow_external_terrain_requests` Valve — separately opt-in because terrain lookups disclose endpoint coordinates
- `allow_region_changes` Valve — separately gated because LoRa region controls regulatory radio parameters
- `allow_secret_output` Valve — controls outputs that inherently contain channel secrets (e.g. share URLs)
- `redact_positions` Valve — optionally redact lat/lon from LLM output
- `rf_earth_k_factor` Valve — configurable effective-Earth-radius factor for path curvature

### Changed
- Tool description updated to reflect RF/link/terrain planning capabilities
- `get_device_summary` now includes `rfPlanning` context
- `get_tool_info` now reports RF planning capability gates

### Security
- External terrain requests are **off by default** and separately opt-in due to coordinate disclosure
- Region changes are **separately gated** from general config writes
- Secret outputs (share URLs) are **blocked by default**

---

## [0.4.0] — 2026-08-15

### Added
- `rf_analyse_mesh` — whole-mesh RF analysis tool (initial version)
- Initial RF region profiles and modem preset data tables
- Terrain elevation API integration framework

### Changed
- Tool description updated to include RF/link/terrain planning
- Internal RF helper methods for link budget, geometry, regulatory assessment

---

## [0.3.0] — 2026-08-08

### Added
- **Initial RF planning tools:**
  - `rf_analyse_link` — link analysis using live LoRa settings and NodeDB data
  - `rf_compare_antennas` — antenna system comparison with regulatory checks
  - `rf_plan_link` — point-to-point link planning with Fresnel/horizon geometry
- RF context derivation from live Meshtastic interface (frequency, TX power, modem preset, sensitivity estimation)
- Regulatory radiated-power assessment (EIRP/ERP) with encoded region limits
- Optional local installation profile Valves for RF calculations

### Changed
- Tool description updated to mention RF/link planning
- Expanded Valves with RF-related configuration options

---

## [0.2.0] — 2026-07-25

### Added
- **Full diagnostics suite:**
  - `get_tool_info` — version, host and capability gates
  - `test_connection` — TCP and protocol connectivity check
  - `get_device_summary` — concise device health summary
  - `get_nodes` / `search_nodes` / `get_node` — NodeDB browsing
  - `get_mesh_health` — SNR/hops/battery statistics
  - `get_config` / `get_config_schema` — configuration inspection
  - `get_channels` / `get_channel_schema` / `get_share_url` — channel inspection
  - `request_telemetry` — on-demand telemetry from any node
  - `request_position` — request a position update
  - `traceroute` — Meshtastic traceroute with structured output
  - `listen_for_packets` — temporary live packet capture
- **Messaging (opt-in):**
  - `send_message` — text messages with acknowledgement support
  - `send_alert` — high-priority alert messages
- **Configuration management (opt-in):**
  - `preview_config_change` / `preview_config_batch` — validate without writing
  - `set_config_value` / `apply_config_batch` — apply changes with confirmation
  - `set_channel_value` / `set_channel_psk` / `delete_channel` / `import_channel_url` — channel management
  - `set_node_name` — set the local node name
- **NodeDB management (opt-in):**
  - `set_node_favorite` / `set_node_ignored` / `remove_node_from_database` / `reset_node_database`
- **Position management (opt-in):**
  - `set_fixed_position` / `remove_fixed_position`
- **Device administration (opt-in):**
  - `sync_device_time` / `reboot_device` / `shutdown_device`
- **Safety framework:**
  - Read-only by default with granular permission Valves
  - Interactive Open WebUI confirmation for mutating operations (`confirm_mutations`)
  - Secret redaction (`redact_secrets`)
  - Factory reset, rebootOTA and DFU mode deliberately excluded

### Security
- All mutating operations require explicit Valve enablement
- Secrets redacted by default
- Interactive confirmation required for mutations by default

---

## Versions before 0.2.0

Initial experimental versions were not publicly released. The tool was developed
privately before the first community release on the Open WebUI platform.