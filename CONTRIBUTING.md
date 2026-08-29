# Contributing to the Meshtastic Open WebUI Tool

Thank you for your interest in contributing! This tool gives an LLM direct access to a Meshtastic radio, so safety and correctness are especially important.

## Code of Conduct

Be respectful and constructive. This is a community project built on shared enthusiasm for Meshtastic and local AI.

## How to contribute

### Reporting bugs

1. Check the [existing issues](https://github.com/beecho01/open-webui-tool-meshtastic/issues) to avoid duplicates
2. Open a bug report using the [bug template](https://github.com/beecho01/open-webui-tool-meshtastic/issues/new?labels=bug&template=bug-report.md)
3. Include the tool version, Open WebUI version, Meshtastic SDK version, firmware version, and hardware
4. **Redact all secrets** (PSKs, passwords, keys, node IDs if sensitive) before sharing output

### Suggesting features

1. Open a feature request using the [feature template](https://github.com/beecho01/open-webui-tool-meshtastic/issues/new?labels=enhancement&template=feature-request.md)
2. Describe the use case — what would you ask the model to do?
3. If the feature involves RF calculations, device mutations, or external data requests, note any safety or privacy implications

### Pull requests

1. **Fork** the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes in the relevant version file (e.g. `meshtastic_0.4.1.py`)
4. **Test against a real Meshtastic node** — this tool interacts with live radio hardware and cannot be meaningfully tested without one
5. Update the [CHANGELOG.md](CHANGELOG.md) under an `[Unreleased]` section
6. Update the [README.md](README.md) if you've added new tools, Valves, or features
7. Commit with a clear message: `git commit -m 'Add rf_analyse_interference tool'`
8. Push: `git push origin feature/your-feature-name`
9. Open a pull request

## Safety guidelines

This tool is designed to be **safe by default**. When contributing, please follow these principles:

### Read-only by default
- Any new tool that mutates the device must be gated behind a permission Valve that defaults to `False`
- Any new tool that sends data externally must be separately opt-in

### Secret handling
- Never expose PSKs, passwords, private keys, or other secrets to the LLM without an explicit `allow_secret_output`-style gate
- Use the existing `_redact` / `_clean_data` helpers to mask sensitive fields

### Mutations
- Mutating tools should use the `_confirm` helper for interactive Open WebUI confirmation when `confirm_mutations` is enabled
- Factory reset, DFU mode, and similar recoverability-impacting operations should **not** be exposed

### RF calculations
- Always distinguish calculated free-space performance from real-world range
- Report data sources and confidence levels for numeric outputs
- TX power should be derived from configuration/firmware limits, not assumed to be measured
- Regulatory data is for planning only — local law always takes precedence

### External requests
- Any external API calls (e.g. terrain elevation) must be opt-in with a clear privacy note about what data is sent where

## Versioning

This project uses a single-file distribution model — each release is a standalone `.py` file (e.g. `meshtastic_0.4.1.py`). When making changes:

1. Work on the current version file
2. Bump the version in the file header (`version: x.y.z`)
3. Copy the final file to `releases/` with the version in the filename
4. Update `CHANGELOG.md`

Version numbering follows [Semantic Versioning](https://semver.org/):
- **Patch** (0.4.1 → 0.4.2): bug fixes, minor improvements
- **Minor** (0.4.1 → 0.5.0): new features, backward-compatible
- **Major** (0.4.1 → 1.0.0): breaking changes

## Testing

There is no automated test suite — this tool requires a live Meshtastic node. When testing your changes:

1. Test read-only tools first with a connected node
2. Test mutating tools with `confirm_mutations` enabled
3. Verify that permission Valves correctly block operations when disabled
4. Verify that secrets are redacted in output
5. If adding RF features, verify calculations against known values

## Questions?

Open a [discussion](https://github.com/beecho01/open-webui-tool-meshtastic/discussions) or an issue — happy to help!