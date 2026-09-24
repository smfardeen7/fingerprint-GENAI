# GenAI Traffic Fingerprinting — implementation guide

Developed a CS 692 research toolkit for classifying known service/mode labels from packet size, timing, direction and burst features. Implemented PCAP/PCAPNG import, grouped dataset checks, six baseline/classifier families, 5/10/30-second observation windows, network-transfer experiments and scenario-group bootstrap intervals. The pipeline exports models, metrics and an offline HTML report. The published demonstration uses synthetic sessions; its scores validate the software workflow, not identification of real GenAI services.

![Source-derived architecture for GenAI Traffic Fingerprinting](images/project-overview.png)

The graphic describes the checked-in implementation. It is an architecture diagram, not a screenshot, a benchmark result or evidence of a live production deployment.

## Source map

- **Packet traces:** PCAP / PCAPNG import and collection worksheets. See [genai_fingerprint/packets.py](../genai_fingerprint/packets.py).
- **Observe metadata:** Size, timing, direction and burst features at 5 / 10 / 30 s. See [genai_fingerprint/features.py](../genai_fingerprint/features.py).
- **Grouped splits:** Six classifier baselines and network-transfer evaluation. See [genai_fingerprint/models.py](../genai_fingerprint/models.py).
- **Inspect evidence:** Bootstrap intervals, saved models and offline HTML report. See [genai_fingerprint/report.py](../genai_fingerprint/report.py).

## Scope

Demonstration data is synthetic. No real ChatGPT, Gemini or other service traffic was collected for this deliverable.

This presentation was checked against source revision `e25b08942b42e13060d3d4dae68fb952225ddd65` on September 24, 2026. The documentation update does not claim a new application test run, cloud deployment or performance measurement.
