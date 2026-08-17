# wa_peer - WhatsApp Desktop call peer-metadata capture

A single-file Frida tool that surfaces the peer-side metadata the WhatsApp for Windows
client **already sees** during a voice or video call. It attaches, for observation only, to
the call-statistics and signalling functions inside `WhatsAppNative.Voip.dll`, collects the
events, and produces a readable JSON dossier.

It generates no new network traffic, changes no value, and calls no WhatsApp function. It
only reads values already present in the application's own memory and writes them out.

---

## Authorized use

This tool makes visible the data your own client sees during calls made with your own
account. Use it only:

- Between your own accounts / your own devices for testing.
- In security research or education where the other party in the call has given explicit
  consent.
- Within an authorized penetration-testing engagement.

Collecting another person's IP address or location without their knowledge and consent is
illegal in many jurisdictions. Responsibility rests with the user.

---

## What data you get

At the end of a call the report describes the **peer** (the other side), the **self** side
(for comparison), and a list of caveats. Each field below is listed with what it is and why
it matters.

### Network / location (`peer.network`) - the highest-value group

| Field | What it is | Why it matters |
|---|---|---|
| `public_endpoints` | The peer's server-reflexive candidates: their **unmasked public IP and port** as seen from the internet, e.g. `203.0.113.45:39284` | This is the location source. Geolocating this IP gives country, city, and carrier. It is the raw signalling address, not masked. |
| `private_endpoints` | The peer's host candidates: their **LAN address** (`192.168.x`, `10.x`) or **carrier-grade NAT** address (`100.64.x`, RFC6598) | A `192.168.x` value means the peer is on home/office Wi-Fi; a `100.64.x` value means they are on mobile data (CGNAT). Delivered even when the two sides are on different networks. |
| `telemetry_view.peer_public_ip_masked` | The same peer IP as WhatsApp records it in **telemetry**, masked to /24 (`203.0.113.0`) | Shows the difference between the masked telemetry path and the unmasked signalling path. The last octet is zeroed here but not in `public_endpoints`. |
| `telemetry_view.peer_lan_prefix_masked` | The peer's LAN prefix as telemetry records it (`192.0.2.0`) | Confirms the peer's local subnet without the host octet. |
| `medium.peer` / `medium.self` | Connection type code for each side: cellular, Wi-Fi/Ethernet, unclassified, or none | Tells you whether the peer was on mobile or fixed-line, corroborating the CGNAT/LAN read above. |
| `nat.symmetric` | Whether the peer is behind a symmetric NAT | Affects whether a direct path is possible; a network-topology hint about the peer. |
| `nat.p2p_disabled` | Whether "Protect IP address in calls" was in effect (WhatsApp's relay-only mode) | If false, the peer's real address was exchanged. If true, only relay addresses appear. |
| `nat.ipv6_capable` | Whether the peer offered IPv6 | Network-stack capability of the peer. |

### Identity / device (`peer.identity`)

| Field | What it is | Why it matters |
|---|---|---|
| `platform` | The peer's platform from the 17-entry enum: android, iphone, windows, web, mac, ipad, etc. | Which OS/app family the peer runs. |
| `app_version` | The peer's WhatsApp version string, e.g. `2.26.30.97` | Narrows the peer's client build; useful for correlation and for spotting outdated clients. |
| `device_class` | WhatsApp's performance tier for the peer's device: High / Mid / Low | Coarse indicator of how new/powerful the peer's phone is. |
| `hardware_year_class` | The peer device's hardware year class, e.g. `2016` | Approximate hardware generation of the peer's device. |
| `linked_device_count` | How many companion devices are linked to the peer's account | Whether the peer uses WhatsApp on multiple devices. |

### Behaviour / fingerprint (`peer.behaviour`, `peer.fingerprint`)

| Field | What it is | Why it matters |
|---|---|---|
| `speech_activity.series` | Per-sample audio-level time series from the peer's stream | Reconstructs the peer's speech vs silence pattern over the call. |
| `speech_activity.max_level` / `mean_level_while_speaking` | Peak and average speaking loudness | Voice-activity profile of the peer. |
| `silence_ms` / `silence_ratio_pct` | How long the peer transmitted nothing (DTX), and as a fraction of the call | How talkative the peer was. |
| `frame_length_ms`, `decode_time_ms`, `jitter_buffer_ms` | Codec/timing values derived from the peer's incoming media | A soft device/network fingerprint of what the peer produced. |
| `uplink_bwe_bps` | Estimated bandwidth of the peer's uplink | Rough capacity of the peer's connection. |

### Correlation (`peer.correlation`)

| Field | What it is | Why it matters |
|---|---|---|
| `abtest_bucket` / `abtest_id_list` | An A/B-test bucket id attached to the peer | Stays constant across calls to the **same device**, so it links multiple calls within a short window. A different device on the same account returns a different value, so it tracks the device, not just the account. |
| `call_ids` | The identifiers seen for this call | Cross-references this call in other logs. |

### Self (`self`)

| Field | What it is | Why it matters |
|---|---|---|
| `public_ip`, `lan_prefix`, `reflexive_ip` | Our own addresses | Included so peer values can be told apart from ours; not peer data. |

### What it does not give

- **No phone number or JID** at this layer; the VoIP layer works with a call id instead.
- **RTT does not give location.** Relay latency is only a coarse network-distance proxy and
  is often not even a real measurement (placeholder values can appear). Use the
  `public_endpoints` IP for location.
- Location from the captured public IP is reliable at the city/carrier level, not the
  street level (especially for mobile IPs, whose addresses come from a base-station pool).

---

## Requirements

- **Windows** (the WhatsApp desktop client runs on Windows).
- **Python 3.8+**.
- **Frida (Python)**: `pip install -r requirements.txt` (works with 16.x or 17.x).
- **WhatsApp for Windows** installed, **running, and signed in** (the Microsoft Store
  build; the process is `WhatsApp.Root.exe`).
- No administrator rights are required. `WhatsApp.Root.exe` is a full-trust Win32 process
  and can be attached from the same user account.

---

## Install

```bash
pip install -r requirements.txt
```

`wa_peer.py` has no other dependency; the Frida agent, the runner, and the report builder
are all inside that one file.

---

## Run

Recommended command (works reliably on Windows PowerShell):

```bash
python wa_peer.py --raw raw.jsonl
```

1. Open WhatsApp for Windows and make sure it is signed in.
2. Run the command above.
3. Wait for this line:

   ```
   attached to WhatsApp.Root.exe - N hooks. Place or accept a call, then Ctrl+C.
   ```

4. **Place a call or accept an incoming call.** The longer the call runs, and the more the
   peer speaks, the fuller the audio-level series. Around 20-30 seconds is enough.
5. **End the call inside WhatsApp first**, wait 2-3 seconds, then return to the terminal and
   press **Ctrl+C**. The report is printed to the screen.

### Two things that will bite you

- **Do not use `> dossier.json` with Ctrl+C in PowerShell.** PowerShell discards a
  redirected file when you interrupt with Ctrl+C, leaving `dossier.json` empty (0 bytes)
  even though the capture worked. Either run without redirection (the report prints to the
  screen), or use `--raw raw.jsonl` so events are written to the file as they arrive, or use
  `--seconds N` so the tool stops on its own. If you still want a saved report file, use
  `--seconds N > dossier.json` (auto-stop writes the file cleanly; Ctrl+C does not).
- **End the call before you stop the tool.** Fields like `app_version`, `device_class`,
  `hardware_year_class`, `medium`, and `nat` come from the call's end-of-call statistics,
  which WhatsApp only produces when the call actually ends. If you press Ctrl+C while the
  call is still connected, those fields come back `null` (the IP, LAN address, platform, and
  speech series still work). Hang up in WhatsApp first, then stop the tool.

### Variants

```bash
python wa_peer.py                      # print to screen, do not save
python wa_peer.py --seconds 60         # stop automatically after 60 s
python wa_peer.py --raw raw.jsonl > dossier.json   # also write raw events to raw.jsonl
python wa_peer.py --compact            # single-line JSON, for scripting
```

### Arguments

| Argument | Meaning |
|---|---|
| `--process NAME` | Process to attach to (default `WhatsApp.Root.exe`) |
| `--seconds N` | Auto-stop after N seconds (0 = until Ctrl+C) |
| `--raw PATH` | Also write the raw event stream (JSONL) to this file |
| `--compact` | Print the report JSON on one line, no indentation |

### First check

Look at the `hook_ready` event at the top of the output. If its `hooked` list is populated,
everything is wired. If the list is empty or short, the WhatsApp version does not match the
tool's offsets (see below).

---

## Version dependency (important)

The offsets (RVAs) inside the agent are for `WhatsAppNative.Voip.dll` **2.2631.102.0**. If
WhatsApp updates, these addresses shift and the hooks either go quiet or destabilise the
process. The Ghidra address equals RVA + 0x180000000.

Moving to a new version requires re-deriving the offsets. To validate a port, confirm
`platform_to_cstr` still returns the **17-entry** platform table (0 = unknown ... 16 = web)
and that known values hold (on a 1:1 call `num_connected_participants == 2`, on a voice
call `video_enabled == 0`).

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `dossier.json` is empty / 0 bytes | You used `> dossier.json` and stopped with Ctrl+C in PowerShell; the redirected file is discarded. Run without redirection, or use `--raw`, or use `--seconds N` |
| `app_version` / `device_class` / `medium` / `nat` all `null` | You stopped the tool while the call was still connected; these come from end-of-call stats. Hang up in WhatsApp first, then Ctrl+C |
| `WhatsApp.Root.exe is not running` | Client closed, or a different process name; pass `--process` |
| `hook_ready` arrived but `hooked` is short/empty | DLL version does not match the offsets (see above) |
| No `endpoint` events | The call did not actually connect; the peer must answer and media must flow |
| Audio series empty | The peer did not speak; DTX produces zero during silence |
| Frida attach error | Frida version and Python bindings mismatch; `pip install -U frida` |

---

