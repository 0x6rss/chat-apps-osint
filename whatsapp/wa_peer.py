
"""WhatsApp for Windows call peer-metadata capture. See README.md for usage."""

import argparse
import collections
import json
import struct
import sys
import time

try:
    import frida
except ImportError:
    print("frida not installed:  pip install frida", file=sys.stderr)
    sys.exit(1)

PROCESS = "WhatsApp.Root.exe"

AGENT = r"""
'use strict';

var VOIP = 'WhatsAppNative.Voip.dll';

var RVA = {
  wa_call_set_field_stat_numeric:                       0x68600,
  wa_call_set_field_stat_str:                           0x68900,
  parse_endpoint_address:                              0x2853B0,
  platform_to_cstr:                                    0x20C1E0,
  wa_transport_get_peer_public_addr_str:               0x415270,
  wa_call_participant_get_peer_test_bucket_id_list_str: 0x20A4A0,
  wa_call_participant_get_peer_test_bucket_str:        0x20A450,
  wa_call_participant_get_multi_device_info_count:     0x20A890,
  wa_call_participant_get_active_device_info_const:    0x20A7B0,
  wa_call_participant_get_audio_level:                 0x20B8A0,
  wa_call_participant_get_offer_msg:                   0x20AB80,
};

var PLATFORM = ['unknown','android','iphone','wp','ios_tablet','kaios','windows',
  'portal','mac_os_electron','windows_electron','wearm','macos','capi','ipad',
  'smba','smbi','web'];

var OFF_PLATFORM = 0x58;

function emit(ev, data) { data = data || {}; data.event = ev; data.ts = Date.now(); send(data); }

function cstr(p) {
  try { return (p === null || p.isNull()) ? null : p.readUtf8String(); }
  catch (e) { return null; }
}

function moduleBase(name) {
  var lower = name.toLowerCase();
  try {
    if (typeof Module.findBaseAddress === 'function') {
      var b = Module.findBaseAddress(name);
      if (b) return b;
    }
  } catch (e) {}
  try {
    if (typeof Process.findModuleByName === 'function') {
      var m = Process.findModuleByName(name);
      if (m) return m.base;
    }
  } catch (e) {}
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      if (String(mods[i].name).toLowerCase() === lower) return mods[i].base;
    }
  } catch (e) {}
  return null;
}

function main() {
  var base = moduleBase(VOIP);
  if (base === null) { emit('error', { message: VOIP + ' not loaded' }); return; }
  function at(n) { return base.add(RVA[n]); }
  var hooked = [];

  try {
    Interceptor.attach(at('wa_call_set_field_stat_numeric'), {
      onEnter: function (args) {
        var name = cstr(args[1]);
        if (!name) return;
        var v = null;
        try { v = this.context.rsp.add(0x38).readDouble(); } catch (e) {}
        emit('field_stat', { name: name, field_id: args[2].toInt32(), value: v });
      }
    });
    hooked.push('field_stat_numeric');
  } catch (e) { emit('hook_error', { fn: 'field_stat_numeric', err: String(e) }); }

  try {
    Interceptor.attach(at('wa_call_set_field_stat_str'), {
      onEnter: function (args) {
        var name = cstr(args[1]);
        if (!name) return;
        emit('field_stat_str', { name: name, field_id: args[2].toInt32(), value: cstr(args[3]) });
      }
    });
    hooked.push('field_stat_str');
  } catch (e) { emit('hook_error', { fn: 'field_stat_str', err: String(e) }); }

  try {
    var seenEp = {};
    Interceptor.attach(at('parse_endpoint_address'), {
      onEnter: function (args) { this.out = args[1]; },
      onLeave: function (ret) {
        if (ret.toInt32() === 0 || this.out.isNull()) return;
        try {
          var o = this.out;
          var v4 = o.add(0x18).readU8() !== 0, v6 = o.add(0x19).readU8() !== 0;
          var rec = {};
          if (v4) {
            var b = new Uint8Array(o.readByteArray(4));
            rec.ipv4 = b[0] + '.' + b[1] + '.' + b[2] + '.' + b[3];
            rec.ipv4_port = o.add(0x14).readU16();
          }
          if (v6) {
            var c = new Uint8Array(o.add(4).readByteArray(16)), parts = [];
            for (var k = 0; k < 16; k += 2) parts.push(((c[k] << 8) | c[k+1]).toString(16));
            rec.ipv6 = '[' + parts.join(':') + ']';
            rec.ipv6_port = o.add(0x16).readU16();
          }
          var key = (rec.ipv4 || rec.ipv6) + ':' + (rec.ipv4_port || rec.ipv6_port);
          if (seenEp[key]) return;
          seenEp[key] = 1;
          emit('endpoint', rec);
        } catch (e) {}
      }
    });
    hooked.push('parse_endpoint_address');
  } catch (e) { emit('hook_error', { fn: 'parse_endpoint_address', err: String(e) }); }

  try {
    var lastPlat = null;
    Interceptor.attach(at('wa_call_participant_get_active_device_info_const'), {
      onLeave: function (ret) {
        if (ret.isNull()) return;
        try {
          var p = ret.add(OFF_PLATFORM).readU32();
          if (p === 0 || p === lastPlat) return;
          lastPlat = p;
          emit('peer_platform', {
            platform_id: p,
            platform: (p < PLATFORM.length) ? PLATFORM[p] : 'out_of_range'
          });
        } catch (e) {}
      }
    });
    hooked.push('peer_platform');
  } catch (e) {}

  function scalar(fnName, evName, field) {
    try {
      var lastByCtx = {};
      Interceptor.attach(at(fnName), {
        onEnter: function (args) { this.ctx = args[0].toString(); },
        onLeave: function (ret) {
          var v; try { v = ret.toInt32(); } catch (e) { return; }
          if (lastByCtx[this.ctx] === v) return;
          lastByCtx[this.ctx] = v;
          var rec = { ctx: this.ctx }; rec[field] = v;
          emit(evName, rec);
        }
      });
      hooked.push(evName);
    } catch (e) {}
  }
  scalar('wa_call_participant_get_multi_device_info_count', 'peer_device_count', 'device_count');
  scalar('wa_call_participant_get_audio_level', 'peer_audio_level', 'level');

  try {
    Interceptor.attach(at('wa_transport_get_peer_public_addr_str'), {
      onEnter: function (args) { this.buf = args[1]; },
      onLeave: function () {
        var s = cstr(this.buf);
        if (s) emit('peer_public_addr', { addr: s });
      }
    });
    hooked.push('peer_public_addr');
  } catch (e) {}

  ['wa_call_participant_get_peer_test_bucket_id_list_str',
   'wa_call_participant_get_peer_test_bucket_str'].forEach(function (n) {
    try {
      var last = null;
      Interceptor.attach(at(n), {
        onLeave: function (ret) {
          var s = cstr(ret);
          if (!s || s === last) return;
          last = s;
          emit('peer_test_bucket', { fn: n, value: s });
        }
      });
      hooked.push(n);
    } catch (e) {}
  });

  try {
    var lastOffer = null;
    Interceptor.attach(at('wa_call_participant_get_offer_msg'), {
      onLeave: function (ret) {
        if (ret.isNull()) return;
        try {
          var b = new Uint8Array(ret.readByteArray(192)), runs = [], cur = '';
          for (var i = 0; i < b.length; i++) {
            var c = b[i];
            if (c >= 0x20 && c < 0x7f) cur += String.fromCharCode(c);
            else { if (cur.length >= 8) runs.push(cur); cur = ''; }
          }
          if (cur.length >= 8) runs.push(cur);
          var key = runs.join('|');
          if (!runs.length || key === lastOffer) return;
          lastOffer = key;
          emit('peer_offer_msg', { strings: runs });
        } catch (e) {}
      }
    });
    hooked.push('peer_offer_msg');
  } catch (e) {}

  emit('hook_ready', { module: VOIP, base: base.toString(), hooked: hooked });
}

if (moduleBase(VOIP) !== null) main();
else {
  var iv = setInterval(function () {
    if (moduleBase(VOIP) !== null) { clearInterval(iv); main(); }
  }, 250);
  emit('waiting', { message: VOIP + ' not yet loaded' });
}
"""

META_V4 = [
    ("31.13.0.0", 16), ("157.240.0.0", 16), ("185.60.216.0", 22),
    ("179.60.192.0", 22), ("129.134.0.0", 16), ("66.220.144.0", 20),
    ("69.63.176.0", 20), ("69.171.224.0", 19), ("74.119.76.0", 22),
    ("102.132.96.0", 20), ("103.4.96.0", 22), ("173.252.64.0", 18),
    ("204.15.20.0", 22), ("163.70.128.0", 17), ("57.144.0.0", 14),
]

NETWORK_MEDIUM = {
    0: "unclassified (connected, but type could not be determined)",
    1: "cellular",
    2: "not cellular (Wi-Fi, or Ethernet on a desktop peer)",
    3: "no active network resolved when the stanza was composed",
}

def ip_to_int(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        parts = [int(x) for x in parts]
    except ValueError:
        return None
    if any(p < 0 or p > 255 for p in parts):
        return None
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

def is_meta(ip):
    if not ip:
        return False
    if ":" in ip:
        return ip.lstrip("[").lower().startswith("2a03:2880")
    value = ip_to_int(ip)
    if value is None:
        return False
    for net, bits in META_V4:
        base = ip_to_int(net)
        mask = 0 if bits == 0 else (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        if (value & mask) == (base & mask):
            return True
    return False

def addr_class(ip):
    if not ip:
        return "unknown"
    if ":" in ip:
        return "ipv6"
    try:
        parts = [int(x) for x in ip.split(".")]
    except ValueError:
        return "unknown"
    if len(parts) != 4:
        return "unknown"
    if parts[0] == 10 or (parts[0] == 172 and 16 <= parts[1] <= 31) \
            or (parts[0] == 192 and parts[1] == 168):
        return "private (RFC1918)"
    if parts[0] == 100 and 64 <= parts[1] <= 127:
        return "carrier-grade NAT (RFC6598)"
    if parts[0] == 127:
        return "loopback"
    return "public"

def num_list(text):
    if not text:
        return None
    try:
        return [float(x) for x in str(text).split(",") if x != ""]
    except ValueError:
        return None

def build_report(events):
    numeric, strings = {}, {}
    for e in events:
        if e.get("event") == "field_stat":
            numeric[e["name"]] = e.get("value")
        elif e.get("event") == "field_stat_str":
            strings[e["name"]] = e.get("value")

    stamps = [e["ts"] for e in events if "ts" in e]
    duration_ms = (max(stamps) - min(stamps)) if stamps else 0

    def get(name):
        return numeric.get(name)

    contexts = collections.defaultdict(dict)
    for e in events:
        ctx = e.get("ctx")
        if not ctx:
            continue
        entry = contexts[ctx]
        entry["events"] = entry.get("events", 0) + 1
        if e.get("event") == "peer_device_count":
            entry["device_count"] = e.get("device_count")
    peer_ctx = None
    for ctx, entry in contexts.items():
        if entry.get("device_count"):
            peer_ctx = ctx

    relays, peer_side, seen = [], [], set()
    for e in events:
        if e.get("event") != "endpoint":
            continue
        for ip, port in ((e.get("ipv4"), e.get("ipv4_port")),
                         (e.get("ipv6"), e.get("ipv6_port"))):
            if not ip or (ip, port) in seen:
                continue
            seen.add((ip, port))
            row = {"ip": ip, "port": port, "address_class": addr_class(ip.strip("[]"))}
            (relays if is_meta(ip) else peer_side).append(row)

    public_eps = [e for e in peer_side if e["address_class"] == "public"]
    private_eps = [e for e in peer_side
                   if "private" in e["address_class"] or "carrier" in e["address_class"]]

    our_rtt = num_list(strings.get("relay_measured_c2r_rtt_list"))
    peer_rtt = num_list(strings.get("relay_measured_max_peer_c2r_rtt_list"))
    servers = [s.strip() for s in (strings.get("call_relay_servers") or "").split(",") if s.strip()]

    latency, degenerate = [], None
    if our_rtt and peer_rtt and len(our_rtt) == len(peer_rtt):

        degenerate = (len(set(peer_rtt)) == 1) or any(v < 0 for v in peer_rtt)
        for i, (ours, theirs) in enumerate(zip(our_rtt, peer_rtt)):
            delta = theirs - ours
            latency.append({
                "relay": servers[i] if i < len(servers) else None,
                "our_rtt_ms": ours, "peer_rtt_ms": theirs, "delta_ms": delta,

                "_note": ("peer is closer to this relay than we are"
                          if delta < 0 else
                          "peer is farther from this relay than we are"),
            })

    levels = [(e["ts"], e.get("level")) for e in events
              if e.get("event") == "peer_audio_level"
              and (peer_ctx is None or e.get("ctx") == peer_ctx)]
    speech = None
    if levels:
        t0 = levels[0][0]
        vals = [v for _, v in levels if v is not None]
        loud = [v for v in vals if v > 0]
        speech = {
            "samples": len(levels),
            "approx_interval_ms": round((levels[-1][0] - t0) / max(1, len(levels) - 1)),
            "max_level": max(vals) if vals else None,
            "mean_level_while_speaking": round(sum(loud) / len(loud), 1) if loud else None,
            "silent_samples": len(vals) - len(loud),
            "series": [{"t_ms": t - t0, "level": v} for t, v in levels],
            "_note": "speech energy sampled by the client; zeros are silence",
        }

    platform = strings.get("call_peer_platform")
    for e in events:
        if e.get("event") == "peer_platform" and not platform:
            platform = e.get("platform")

    device_count = None
    for e in events:
        if e.get("event") == "peer_device_count" and e.get("device_count"):
            device_count = e.get("device_count")

    call_ids = []
    for e in events:
        if e.get("event") == "peer_offer_msg":
            call_ids.extend(e.get("strings") or [])

    medium_peer, medium_self = get("peer_call_network"), get("call_network")

    return {
        "capture": {
            "events": len(events),
            "duration_s": round(duration_ms / 1000.0, 1),
            "numeric_fields": len(numeric),
            "string_fields": len(strings),
        },
        "peer": {
            "identity": {
                "platform": platform,
                "app_version": strings.get("call_peer_app_version"),
                "device_class": strings.get("device_class"),
                "hardware_year_class": get("peer_year_class_2016"),
                "linked_device_count": device_count,
                "_note": "platform from the 17-entry platform_to_cstr enum; "
                         "device count from multi_device_info_count",
            },
            "network": {
                "public_endpoints": [
                    dict(e, _note="server-reflexive candidate from call signalling "
                                  "— full address and port, not masked")
                    for e in public_eps],
                "private_endpoints": [
                    dict(e, _note="host candidate from the peer's own LAN or carrier "
                                  "NAT; delivered even when the two sides are on "
                                  "different networks")
                    for e in private_eps],
                "telemetry_view": {
                    "peer_public_ip_masked": strings.get("call_peer_ip_str"),
                    "peer_lan_prefix_masked": strings.get("peer_local_ip_prefix"),
                    "_note": "the telemetry path masks the peer address to /24 while "
                             "the signalling path above does not",
                },
                "medium": {
                    "peer": medium_peer,
                    "peer_meaning": NETWORK_MEDIUM.get(int(medium_peer)) if medium_peer is not None else None,
                    "self": medium_self,
                    "self_meaning": NETWORK_MEDIUM.get(int(medium_self)) if medium_self is not None else None,
                },
                "nat": {
                    "symmetric": bool(get("is_in_sym_nat")) if get("is_in_sym_nat") is not None else None,
                    "ipv6_capable": bool(get("is_ipv6_capable")) if get("is_ipv6_capable") is not None else None,
                    "p2p_disabled": bool(get("call_p2p_disabled")) if get("call_p2p_disabled") is not None else None,
                    "_note": "p2p_disabled is the desktop equivalent of Android's "
                             "disallowAllP2P(). False means 'Protect IP address in "
                             "calls' was not in effect. Media going over a relay does "
                             "not imply the address was protected — candidates are "
                             "still exchanged either way.",
                },
            },
            "relays": {
                "servers": servers,
                "observed_candidates": [
                    dict(r, _note="Meta infrastructure — the relay, not the peer")
                    for r in relays],
                "latency": latency,
                "latency_usable": (None if degenerate is None else not degenerate),
                "latency_spread_ms": (round(max(peer_rtt) - min(peer_rtt), 1)
                                      if peer_rtt and not degenerate else None),
                "_note": "identical or negative peer values are placeholders; no "
                         "location inference can be drawn from them. A mixed "
                         "profile (closer to some relays, farther from others) "
                         "is more discriminating than a uniform one.",
            },
            "behaviour": {
                "speech_activity": speech,
                "silence_ms": get("dtx_rx_duration_t"),
                "silence_ratio_pct": (round(100.0 * get("dtx_rx_duration_t") / duration_ms, 1)
                                      if get("dtx_rx_duration_t") and duration_ms else None),
                "_note": "dtx_rx_duration_t is how long the peer transmitted nothing",
            },
            "fingerprint": {
                "frame_length_ms": get("avg_rx_frame_length_ms"),
                "decode_time_ms": get("avg_decode_t"),
                "jitter_buffer_ms": get("jb_avg_delay"),
                "uplink_bwe_bps": get("call_rx_avg_bwe"),
                "_note": "rx-side values describe what the peer produced",
            },
            "correlation": {
                "abtest_bucket": strings.get("call_peer_test_bucket"),
                "abtest_id_list": strings.get("call_peer_test_bucket_id_list"),
                "call_ids": call_ids,
                "_note": "the bucket id was identical across three calls to the same "
                         "device, so it links calls over a short window. It tracks the "
                         "DEVICE: another device on the same account gave a different "
                         "platform, version and LAN address.",
            },
        },
        "self": {
            "public_ip": strings.get("call_self_ip_str"),
            "lan_prefix": strings.get("local_ip_prefix"),
            "reflexive_ip": strings.get("signaling_reflexive_ip_self"),
            "_note": "included so peer values can be told apart from ours",
        },
        "participant_contexts": [
            {"ctx": ctx,
             "role": "peer" if ctx == peer_ctx else ("self" if peer_ctx else "unknown"),
             "device_count": entry.get("device_count"),
             "events": entry.get("events")}
            for ctx, entry in contexts.items()],
        "caveats": [
            "No JID or phone number exists on this layer — confirmed across three "
            "runs; the VoIP layer works with a call id instead.",
            "No location data in call signalling; relay latency is the only "
            "geographic proxy and it is not always a real measurement.",
            "battery_low is present in telemetry but which side it belongs to was "
            "never established.",
            "WAM hooks did not fire during calls, so the messaging surface is not "
            "covered here.",
        ],
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--process", default=PROCESS)
    ap.add_argument("--seconds", type=float, default=0, help="0 = until Ctrl+C")
    ap.add_argument("--raw", metavar="PATH", help="also write the raw event stream")
    ap.add_argument("--compact", action="store_true")
    args = ap.parse_args()

    try:
        session = frida.attach(args.process)
    except frida.ProcessNotFoundError:
        print(json.dumps({"error": "%s is not running" % args.process}, indent=2))
        return 1

    events = []
    raw_file = open(args.raw, "a", encoding="utf8") if args.raw else None

    def on_message(message, data):
        if message.get("type") == "error":
            print("[agent error] %s" % message.get("description"), file=sys.stderr)
            return
        payload = message.get("payload")
        if payload is None:
            return
        events.append(payload)
        if raw_file:
            raw_file.write(json.dumps(payload, ensure_ascii=False) + "\n")
            raw_file.flush()
        if payload.get("event") == "hook_ready":
            print("attached to %s — %d hooks. Place or accept a call, then Ctrl+C."
                  % (args.process, len(payload.get("hooked", []))), file=sys.stderr)

    script = session.create_script(AGENT)
    script.on("message", on_message)
    script.load()

    deadline = time.time() + args.seconds if args.seconds else None
    try:
        while True:
            if deadline and time.time() > deadline:
                break
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass
    finally:
        if raw_file:
            raw_file.close()
        try:
            session.detach()
        except Exception:
            pass

    report = build_report(events)
    print(json.dumps(report, indent=None if args.compact else 2, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    sys.exit(main())
