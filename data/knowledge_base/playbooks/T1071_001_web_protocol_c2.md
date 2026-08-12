# Suspicious Web-Protocol C2 / Network Connection Response Playbook
Technique: T1071.001

## Detection Context
Malware commonly blends command-and-control (C2) traffic into HTTP/HTTPS to evade network
detection, since these ports are almost never blocked outbound. In Sysmon Event ID 3
(network connection), suspicious signals include: a non-browser process (e.g. `powershell.exe`,
`rundll32.exe`, `regsvr32.exe`, an unsigned binary in `%TEMP%`) making outbound connections
on port 80/443; connections to IP-literal destinations instead of domains; periodic
"beaconing" connections at regular intervals; connections to newly-registered or low-reputation
domains; and unusual destination countries/ASNs relative to the organization's normal traffic.

## Investigation Steps
1. Identify the initiating process (`Image`) and confirm whether it is expected to make
   outbound web requests at all.
2. Resolve the destination IP/domain and check reputation (age of domain, hosting provider,
   any open threat-intel hits).
3. Look for beaconing patterns — repeated connections at fixed intervals to the same
   destination are a strong C2 indicator versus normal bursty user browsing.
4. Correlate with the process's parent chain and any recent file-creation or
   scheduled-task events on the same host to find the initial infection vector.
5. Check whether other hosts on the network are contacting the same destination
   (potential lateral spread or shared C2 infrastructure).

## Containment
- Block the destination IP/domain at the firewall/proxy/DNS layer.
- Isolate the host from the network to stop further C2 communication.
- Kill the offending process.

## Remediation
- Capture memory/disk artifacts from the host before reimaging if the intrusion is
  confirmed active.
- Add the C2 indicators (IP, domain, JA3/TLS fingerprint if available) to blocklists.
- Review egress filtering rules — restricting outbound traffic to known-good destinations
  reduces the impact of this technique going forward.
