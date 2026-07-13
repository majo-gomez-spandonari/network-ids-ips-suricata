# Network IDS/IPS Lab — Suricata on Kali Linux

## Objective
Deploy and configure Suricata as an Intrusion Detection System (IDS) on
Kali Linux, then write and test custom detection rules against live
network traffic.

## Environment
- Host: Kali Linux (IP: 10.0.2.15)
- Interface: eth0 (af-packet capture mode)
- Suricata version: 8.0.5

## What I did

**1. Installation**

```
sudo apt-get install suricata jq
```

Verified the install and confirmed key paths (config, rules, logs) via:

```
whereis suricata
suricata --build-info
service suricata start
service suricata status
```

**2. Network configuration**
Suricata's config file (`suricata.yaml`) is split into 4 sections: network
config, output/logging config, capture settings, and application-layer
protocol config.

Edited `HOME_NET` in the network section to match the actual lab subnet
(10.0.2.0/24) instead of the generic defaults, so detections are accurate
to this environment rather than flagging on mismatched ranges.

**3. Custom rule file**
Rather than editing the default ruleset directly, created a dedicated
rules file so custom detections stay separate and maintainable:

```
sudo touch /etc/suricata/rules/my.rules
```

Pointed `suricata.yaml` at it under `rule-files:`, then restarted the
service to apply the change.

**4. ICMP detection rule**

```
alert icmp any any -> any any (msg:"Paquete ICMP encontrado"; sid:1; rev:1;)
```

Alerts on any ICMP traffic (e.g. `ping`) between any source and destination.

Tested by tailing the live log in one terminal:

```
tail -f /var/log/suricata/fast.log
```

and generating traffic in another:

```
ping -c 4 8.8.8.8
```

**Result:** Suricata correctly logged each ICMP packet in real time.

**5. Application-layer detection rule (Facebook)**

```
alert tcp any any -> any any (msg:"Facebook detectado"; content:"facebook"; sid:2; rev:1;)
```

Alerts on TCP traffic containing "facebook" in the packet content — a basic
content-match rule rather than IP-based, so it triggers regardless of which
IP Facebook resolves to.

Tested with:

```
curl -i facebook.com
```

**Result:** Suricata captured the connection and logged a match in both
directions (client → server and server → client), confirming the rule
correctly inspects payload content, not just headers.

## Key result
Suricata successfully detected both a low-level network probe (ICMP) and
an application-layer connection (HTTP to a specific domain) using two
different rule-matching approaches — address/protocol-based and
content-based. This mirrors the two most common detection strategies used
in real IDS/IPS deployments: network-layer anomaly rules and payload
inspection rules.

## Notes
- IPv6 link-local traffic (`fe80::...`) also appeared in the ICMP alerts
  alongside IPv4 — worth remembering when tuning rules in dual-stack
  environments, since a rule intended for IPv4-only monitoring may need
  explicit protocol scoping to avoid noise.

## Files in this repo
- `rules/my.rules` — custom detection rules
- `screenshots/` — terminal output showing install, config, and live alerts
