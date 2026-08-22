# wa_peer - WhatsApp Desktop call peer-metadata capture

A single-file Frida tool that surfaces the peer-side metadata the WhatsApp for
Windows client already sees during a voice or video call. It attaches for
observation only, reads values already present in the application's own memory,
and writes them out. It generates no new network traffic and changes no value.

Use it only between your own accounts/devices, in research or education where the
other party has given explicit consent, or within an authorized engagement.

---

## Requirements

- Windows (the WhatsApp desktop client runs on Windows).
- Python 3.8+.
- Frida (Python): `pip install -r requirements.txt` (works with 16.x or 17.x).
- WhatsApp for Windows installed, running, and signed in (process
  `WhatsApp.Root.exe`). No administrator rights are required.

## Install

```
pip install -r requirements.txt
```

## Run

```
python wa_peer.py
```

1. Open WhatsApp for Windows and make sure it is signed in.
2. Run the command above and wait for the line:
   `attached to WhatsApp.Root.exe ... - N hooks. Place or accept a call, then Ctrl+C.`
3. Place or accept a call. Around 20-30 seconds is enough; the more the peer
   speaks, the fuller the audio-level series.
4. End the call inside WhatsApp first, wait 2-3 seconds, then press Ctrl+C.

Two things to know:

- End the call before you stop the tool. Fields such as `app_version`,
  `device_class`, `medium`, and `nat` come from end-of-call statistics that only
  exist once the call actually ends.
- Do not use `> file.json` together with Ctrl+C in PowerShell; PowerShell
  discards the redirected file on interrupt. Use `--seconds N`, or `--raw`, or
  read the report from the screen.

### Variants

```
python wa_peer.py --seconds 60     # stop automatically after 60 s
python wa_peer.py --no-geo         # skip the online IP geolocation lookup
python wa_peer.py --compact        # print the report JSON on one line
python wa_peer.py --raw raw.jsonl  # also write the raw event stream (JSONL)
```

### Arguments

| Argument | Meaning |
|---|---|
| `--process NAME` | Process to attach to (default `WhatsApp.Root.exe`) |
| `--seconds N` | Auto-stop after N seconds (0 = until Ctrl+C) |
| `--raw PATH` | Also write the raw event stream (JSONL) to this file |
| `--no-geo` | Skip the online IP geolocation lookup (fully offline) |
| `--no-browser` | Write the HTML report but do not open it |
| `--outdir DIR` | Where to write the JSON and HTML report (default: current dir) |
| `--compact` | Print the report JSON on one line |

## Output

Each run writes two files and prints the report to the screen:

- `wa_peer_full_<timestamp>.json` - the full dossier (every captured field).
- `wa_peer_report_<timestamp>.html` - a dashboard that opens in the browser. It
  has a language selector (Turkish, English, Russian, Arabic, Chinese) and a map
  of the peer's IP location.

---

## What the data means

### Network / location (`peer.network`)

| Field | What it is |
|---|---|
| `public_endpoints` | The peer's unmasked public IP and port as seen from the internet. This is the location source. |
| `private_endpoints` | The peer's LAN address (`192.168.x`, `10.x`) or carrier-grade NAT address (`100.64.x`). A private value means home/office Wi-Fi; a CGNAT value means mobile data. |
| `geolocation` | Country, region, city, coordinates, ISP, and AS for the peer's public IP, resolved via ip-api.com. Drives the map. |
| `telemetry_view.peer_public_ip_masked` | The same peer IP as WhatsApp records it in telemetry, masked to /24. |
| `medium.peer` / `medium.self` | Connection type for each side: cellular, Wi-Fi/Ethernet, or none. |
| `nat.symmetric` | Whether the peer is behind a symmetric NAT. |
| `nat.p2p_disabled` | Whether "Protect IP address in calls" was in effect. If false, the peer's real address was exchanged. |
| `nat.ipv6_capable` | Whether the peer offered IPv6. |

### Identity / device (`peer.identity`)

| Field | What it is |
|---|---|
| `platform` | The peer's platform: android, iphone, windows, web, mac, ipad, etc. |
| `app_version` | The peer's WhatsApp version string, e.g. `2.26.30.97`. |
| `device_class` | WhatsApp's performance tier for the peer's device: High / Mid / Low. |
| `hardware_year_class` | Approximate hardware generation of the peer's device, e.g. `2016`. |
| `linked_device_count` | How many companion devices are linked to the peer's account. |

### Other fields in the JSON

- `peer.behaviour` - speech-activity series, silence duration and ratio.
- `peer.fingerprint` - codec/timing values (frame length, decode time, jitter
  buffer, uplink bandwidth estimate) describing what the peer produced.
- `peer.correlation` - A/B-test bucket id (constant across calls to the same
  device) and the call ids seen for this call.
- `peer.relays` - Meta relay servers and relay latency samples.
- `self` - our own addresses, included so peer values can be told apart.

### Notes

- No phone number or JID exists at this layer; the VoIP layer works with a call
  id instead.
- Location from the captured public IP is reliable at the city/carrier level,
  not the street level (mobile IPs come from a base-station pool).
- Relay latency does not give location; it is only a coarse network-distance
  proxy and is often not a real measurement.
