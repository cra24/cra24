## What this changes

<!-- One or two sentences. The diff says what; say why. -->

## Why

<!-- The problem. If it fixes an issue, link it. -->

## How you know it works

<!-- The test you added, or the command you ran. -->

---

### Checklist

- [ ] Commits carry `Signed-off-by` (`git commit -s`) — see [CLA.md](../CLA.md)
- [ ] New source files carry the SPDX header
- [ ] `pytest` passes
- [ ] `ruff check . && ruff format --check . && mypy` pass
- [ ] `CHANGELOG.md` updated

### If this touches triage

- [ ] A test for what the rule concludes
- [ ] A test for what it **refuses** to conclude when its evidence is absent
- [ ] The rule can only downgrade a verdict, never upgrade one
- [ ] Any justification comes from the closed OpenVEX vocabulary
- [ ] **This may change a verdict for a CVE someone already published a VEX statement about** — flagged under **Triage** in the changelog

### If this touches the field spec

- [ ] `spec_version` bumped
- [ ] `sources` updated with a consultation date
- [ ] Noted under **Field spec** in the changelog

### If this adds an emitter or an emitted field

- [ ] A schema-validation test covering the affected, not-affected and empty cases
