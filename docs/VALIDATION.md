# Validation record

This record describes software verification, not a completed empirical study.

## Executed successfully

- Installed the package in editable mode with the local declared dependencies already present.
- Ran 26 unittest cases successfully; full output is in `test_results.txt`.
- Generated a fresh 360-session, six-class synthetic dataset and validated the 216/72/72 scenario-group and day partitions.
- Imported the generated held-out sample PCAP through the same binary-import path used for real captures.
- Extracted 1,080 prefix rows at 5, 10 and 30 seconds, with 128 behavioral feature columns.
- Ran all six model families in mixed-profile and good-network-transfer experiments at each horizon: 36 comparison rows.
- Selected model settings and deployment models using validation scores only, then evaluated final test scenarios.
- Exported and reloaded all three saved model files; performed 30-second prediction on the held-out synthetic sample.
- Generated CSV/JSON evidence, three PNG figures, and an offline HTML report. Inspected the generated figures.
- Checked the HTML report's 36 result rows and three embedded images. Executed the report's filter/reset JavaScript in Node with controlled document objects; filtering random_forest returns six rows and reset restores 36.
- Generated the real-data collection worksheet and dry-run namespace network command plans. Unit tests exercise refusing unrelated qdiscs and rollback after partial apply failure.
- Tests cover PCAP little/big-endian input, PCAPNG enhanced packet blocks, IPv6, VLAN, Linux cooked headers, malformed/truncated input, unknown-device rejection, prefix boundary causality, metadata exclusion, grouped split checks, duplicate traces, real/synthetic isolation, registration and paired bootstrap.

## Environment limits and remaining verification

- No real phone/provider sessions were captured. No provider access, account sign-in or paid subscription is bundled.
- TShark/tcpdump are unavailable in the build environment. The live-capture wrapper must be exercised on the user's Linux gateway. Confirm interface visibility, permissions, clock alignment, capture drops and actual duration during the pilot.
- Network emulation was not applied to a live topology here. The user's dedicated namespace must have working LAN/WAN routing. Verify both directions and measured delay/rate/loss before collecting experimental data.
- A complete graphical Chromium browser was unavailable. HTML structure and filter logic were checked, and PNG charts were inspected, but this is not a cross-browser rendering certification.
- Binary parser coverage is intentionally finite: timestamp-less/obsolete PCAPNG blocks, unsupported link types, jumbograms and opaque tunnel capture require conversion or an expanded importer.
- Every included metric is synthetic. Toy distributions may make classes artificially easy to distinguish. Their scores cannot support the proposal's real-world targets.

## Reproduce

`python -m unittest discover -s tests -v`

`python -m genai_fingerprint demo --out runs/new_demo`

Runtime versions are pinned in `requirements-tested.txt` and recorded in the generated `summary.json`. The saved sample prediction demonstrates I/O, not the ability to identify arbitrary unseen real applications.
