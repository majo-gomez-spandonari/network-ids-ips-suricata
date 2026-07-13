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

## Part 2 — Suricata as IPS (active blocking, not just detection)
Everything above runs Suricata in IDS mode — it observes a copy of
traffic and alerts, but cannot stop anything. This section configures
Suricata as a true IPS, capable of intercepting and dropping packets
before they reach their destination.

**1. Enable NFQUEUE inline mode**

```
suricata --build-info | grep -i nfqueue
sudo iptables -I INPUT -j NFQUEUE
sudo iptables -I OUTPUT -j NFQUEUE
sudo iptables -vnL
```

This redirects all inbound/outbound traffic through a queue that Suricata
can inspect and decide to accept or drop — the core mechanism that turns
an IDS into an IPS.

Ran Suricata against the queue directly:

```
sudo suricata -c /etc/suricata/suricata.yaml -s /etc/suricata/rules/my2.rules -q 0
```

**2. Block Facebook Traffic (drop, not alert)**

```
drop tcp any any -> any any (msg:"Facebook esta bloqueado"; content:"facebook"; nocase; sid:102; rev:1;)
```

Tested with two HTTP requests via netcat toward the target — one normal,
one containing "facebook" in the URL/Host header.

**Result:** the normal request got a full response; the Facebook-tagged
request got nothing — confirmed dropped in-flight, not just logged.

*Note: used `sid:102` instead of `sid:2` to avoid a duplicate-signature
conflict, since `sid:2` was already in use in `my.rules`, which was still
loaded simultaneously via `rule-files` in `suricata.yaml`. This revealed
that Suricata's `-s` flag adds a rule file to what's already configured —
it doesn't replace it.*

**3. Block SSH connections (drop, not alert)**

```
drop tcp any any -> any 22 (msg:"Conexion SSH bloqueada"; flow:to_server,established; sid:104; rev:1;)
```
Attempted an SSH connection to the target — this time the client hung
indefinitely with no response (not even a host-key prompt), confirming
Suricata dropped the initial connection packet before the handshake
could begin. Contrast with the IDS-mode SSH test earlier, where the
connection succeeded normally and was merely logged.

*After testing, Suricata reported 56 total packets through the NFQUEUE:
34 accepted, 22 dropped — confirming active filtering. Restored normal
connectivity afterward with `sudo iptables -F` .* 

## Part 3 — DNS-layer detection (offline pcap analysis)

Rather than live traffic, this test analyzes a packet capture offline —
a common real-world workflow when investigating traffic after the fact.

Captured DNS queries to several domains:

```
sudo tcpdump -i eth1 -w captura.pcap udp port 53
dig @<target> whatsapp.com
dig @<target> facebook.com
dig @<target> instagram.com
dig @<target> tiktok.com
```

Wrote domain-specific DNS detection rules:

```
alert dns any any -> any any (msg:"Peticion DNS a WhatsApp detectada"; dns.query; content:"whatsapp.com"; nocase; sid:200; rev:1;)
alert dns any any -> any any (msg:"Peticion DNS a Facebook detectada"; dns.query; content:"facebook.com"; nocase; sid:201; rev:1;)
alert dns any any -> any any (msg:"Peticion DNS a Instagram detectada"; dns.query; content:"instagram.com"; nocase; sid:202; rev:1;)
alert dns any any -> any any (msg:"Peticion DNS a TikTok detectada"; dns.query; content:"tiktok.com"; nocase; sid:203; rev:1;)
```

*Troubleshooting note: initially scoped the rules to `$HOME_NET any -> $EXTERNAL_NET 53 `, which generated zero alerts — likely because DNS
response traffic also flows over port 53, and the strict source/dest
scoping filtered out the relevant packets. Removing the address/port
restriction (`any any -> any any`) fixed detection immediately. A good
reminder that DNS's request/response symmetry on a single port needs
looser rule scoping than typical client→server traffic.*

Analyzed the capture offline:

```
sudo suricata -r captura.pcap -c /etc/suricata/suricata.yaml -s /etc/suricata/rules/my3.rules -l ./
```
**Result:** all domain queries correctly detected in `fast.log.`.

## Part 4 — Emerging Threats ruleset integration

Moving beyond custom rules, integrated the community-maintained Emerging
Threats Open ruleset via Suricata's built-in updater:

```
sudo suricata-update
```

This generated 66,753 rules, of which 50,824 were enabled after
automatic filtering disabled unused protocols (pgsql, modbus, dnp3, enip).

Copied the generated ruleset to the configured rules path and enabled it
alongside the existing custom rules:

```
sudo cp /var/lib/suricata/rules/suricata.rules /etc/suricata/rules/suricata.rules
```

```yaml
rule-files:
  - suricata.rules
  - my.rules
```

```
sudo service suricata restart
sudo service suricata status
```

Memory usage jumped from the typical 30–70MB (custom rules only) to
511MB, reflecting the much larger ruleset now loaded.

Verified the exact load status via the Suricata control socket:

```
sudo suricatasc -c "ruleset-stats"
```

**Result:** confirmed **50,828 rules loaded** (Emerging Threats + custom), with `rules_failed:0` and `rules_skipped: 0`.

## Additional key results

- Demonstrated the practical difference between IDS (alert-only) and IPS
(active drop) modes using the same rule logic against Facebook and SSH
traffic
- Performed DNS-layer detection via offline pcap analysis — a realistic
incident-investigation workflow, not just live monitoring
- Integrated a production-scale community ruleset (Emerging Threats,
~50K active rules) alongside custom detection logic

## Additional files in this repo
- `pcaps/` -DNS query capture used offline analysis
 
