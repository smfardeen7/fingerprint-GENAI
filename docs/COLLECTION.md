# Real-data collection protocol

## Scope and prerequisites

Use two mentor-approved GenAI services with voice and camera/video modes available on the same phone, and one conventional calling application in voice and video modes. Confirm subscriptions, app versions and capture permissions in the pilot. One participant/device and one foreground session are the controlled starting scope. Record changes or exclusions rather than silently modifying labels.

Needed: Linux gateway with a LAN-side capture interface, phone, upstream internet connection and team-controlled conventional-call endpoint. `tshark` is needed for live capture; `iproute2` supplies `ip` and `tc` for emulation. No tools need access to plaintext conversation content. Use nonsensitive scripted scenes and team-owned traffic only. Keep raw captures and device addresses private; share derived metadata/features.

## Session procedure

1. Choose the next row from `configs/collection_plan.csv` for the current split. The worksheet randomizes classes/profiles within a partition. Spread training across days if possible; collect validation later and test later still. Do not move scenarios between partitions after seeing accuracy.
2. Apply and verify the intended gateway profile. Record a baseline RTT measurement, effective throughput from a separate probe, version/tier and device state. Probe traffic should not overlap the capture.
3. Close unrelated foreground apps and pause unrelated downloads. Connect the application, confirm the correct voice/video mode, and leave it ready before starting capture. Maintain comparable device conditions across classes.
4. Start the `capture` command. At its `READY` marker, begin the scenario. Use the same prerecorded user audio, scene, and nominal turn schedule across services for that scenario group. For video mode, show the scene as well. Voice prompts must remain understandable without a camera; spoken scene descriptions can be used in both modes.
5. Aim for turns at about 0, 20 and 40 seconds, but do not speak over a response merely to force timing. Log response overruns/interruptions as deviations. Conventional calls use a team-controlled peer with prerecorded, scenario-matched replies. Their cadence cannot perfectly match generated speech; discuss that confound in the report.
6. Stop after at least 60 active seconds. Inspect the capture log, confirm packets from the test device in both directions and verify capture drops. Register actual timing/date/version fields. A failed capture is not an independent successful sample; log the failure and retry the same worksheet slot.
7. Audit the full manifest before training. Do not tune using test results. Each scenario's classes, network profiles and all repeated attempts belong to one split.

## Twenty scenario groups

These are starter ideas, not measurements. Before collection, write three exact prompts and reference replies for each, record the user audio, and keep the script immutable. Distinct scenarios must use distinct recordings. Use different objects/examples for held-out groups.

| Group | Split | Nonsensitive scene / topic |
|---|---|---|
| 00 | Train | Red mug and blue notebook; compare their uses |
| 01 | Train | Pen and pencil; describe differences |
| 02 | Train | Paper shapes; explain a sorting rule |
| 03 | Train | Three colored blocks; discuss their order |
| 04 | Train | Toy car and ball; compare motion |
| 05 | Train | Spoon and cup; describe a simple arrangement |
| 06 | Train | Printed large letters; make a word |
| 07 | Train | Fictional timetable; plan a short activity |
| 08 | Train | Fruit drawings; describe colors and grouping |
| 09 | Train | Folded paper; explain a folding step |
| 10 | Train | Toy animals; tell a short description |
| 11 | Train | Simple geometric drawing; describe position |
| 12 | Validation | Green bottle and orange card |
| 13 | Validation | A sequence of numbered tiles |
| 14 | Validation | Fictional cafe menu |
| 15 | Validation | Two paper airplanes |
| 16 | Test | Purple box and yellow ribbon |
| 17 | Test | Four wooden shapes in a changing order |
| 18 | Test | Fictional museum opening-hours card |
| 19 | Test | Paper bridge and toy boat |

Keep response-length requests consistent, for example one or two sentences. Do not encode the correct service label into spoken scripts or filenames passed to the feature model. Prompts may naturally influence packet behavior; held-out scenarios assess some of this sensitivity, not generalization to every possible conversation.

## Network shaping

The provided commands only alter explicitly named **network namespaces**. They never modify a default host interface. A working routed lab namespace with distinct LAN/WAN egress interfaces must already exist. Creating that topology, Wi-Fi access point, forwarding/NAT and internet access depends on your hardware and must be configured with your lab administrator/mentor. The project intentionally does not alter your laptop's default route or firewall.

For a disposable lab gateway namespace named `genai-lab`, with egress interfaces `wan` toward the provider and `lan` toward the phone:

```bash
python -m genai_fingerprint network plan --namespace genai-lab \
  --uplink wan --downlink lan --profile constrained

# On your prepared Linux lab gateway, using its Python environment and root privileges:
python -m genai_fingerprint network apply --namespace genai-lab \
  --uplink wan --downlink lan --profile constrained

python -m genai_fingerprint network remove --namespace genai-lab \
  --uplink wan --downlink lan --profile constrained
```

Apply needs root/network-admin privileges. It refuses an existing non-default qdisc and rolls back its first change if applying the second fails. Remove only deletes project-owned handle `692:`. Remove the old profile before applying another one. Inspect and log both qdiscs and verify achieved bandwidth/delay with independent probes.

Each constrained egress adds 50 ms, giving 100 ms additional RTT across the gateway. Each direction receives the rate cap. Lossy adds 1% independent loss in each direction. Good caps at 10 Mbps with no additional delay/loss; it does not mean the underlying internet path has zero latency/loss. `netem` is a controlled approximation, not a full cellular emulator. Capture at a consistent location relative to the shaper for every session; capture timestamps at gateway interfaces need not equal delivery times after queuing.

For capture inside the namespace, run TShark/your capture command using `ip netns exec genai-lab ...` with the LAN interface and the Python environment that contains the project. Offline import, extraction and learning can run on the normal host without elevated privileges.
