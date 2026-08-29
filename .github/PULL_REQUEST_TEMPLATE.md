## Description

Brief description of what this PR changes and why.

## Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] RF planning change
- [ ] Safety/permission change

## Safety checklist

- [ ] New mutating tools are gated behind a permission Valve that defaults to `False`
- [ ] New external data requests are separately opt-in
- [ ] Secrets are redacted in output (no PSKs/passwords/keys exposed to the LLM)
- [ ] Mutating tools use `_confirm` for interactive confirmation
- [ ] No recoverability-impacting operations added (factory reset, DFU, etc.)
- [ ] RF calculations distinguish free-space estimates from real-world range
- [ ] RF numeric outputs report data sources and confidence

## Testing

- [ ] Tested against a live Meshtastic node
- [ ] Read-only tools verified
- [ ] Mutating tools verified with `confirm_mutations` enabled
- [ ] Permission Valves correctly block operations when disabled
- [ ] Secret redaction verified

## Documentation

- [ ] CHANGELOG.md updated
- [ ] README.md updated (if new tools/Valves/features added)
- [ ] Version bumped in file header