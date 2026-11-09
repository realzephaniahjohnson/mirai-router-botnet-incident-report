# Hunting and detection queries

These are the queries I used for this investigation. They all run in [Mothlight's](https://mothlight.streamlit.app) Search console against the `honeypot` table, and the results below are what I got on Nov 9, 2026, across about 6,400 honeypot events.

## 1. Finding the cluster (KQL)

None of these bots were on a blocklist, so searching by reputation wasn't an option. I searched for the toolkit instead: the writable-folder probe, the hex writes, the router escape command and the variant marker.

```kql
honeypot
| where command contains ".b && sh" or command contains "busybox echo -ne" or command == "linuxshell" or command contains "busybox V3G4"
| summarize Hits = count(), First = min(time), Last = max(time) by ip
| sort by First asc
```

| ip | Hits | First (UTC) | Last (UTC) |
| --- | --- | --- | --- |
| 167.250.28.185 | 19 | 14:52:23 | 14:52:29 |
| 41.39.79.223 | 1 | 15:38:26 | 15:38:26 |
| 31.171.66.62 | 19 | 16:13:48 | 16:13:50 |

Only three IPs in the whole dataset matched, and none of them are on a single blocklist.

## 2. Pulling one full session (KQL)

```kql
honeypot
| where ip == "167.250.28.185"
| project time, event, username, password, command
| sort by time asc
```

That returns all 42 events from the Brazil bot's 8-second session. The full logs for all three bots are in [`evidence/`](../evidence/).

## 3. The same hunt in SPL

```spl
index=honeypot (command="*.b && sh*" OR command="*busybox echo -ne*" OR command="linuxshell")
| stats count by ip
| sort -count
```

## 4. New detection rule: writable-folder probe

Before a bot drops its payload, it has to find a folder it can write to. This bot family does that by writing an empty `.b` file into one folder after another.

```kql
honeypot
| where event == "command"
| where command contains "/bin/busybox echo >" and command contains ".b && sh"
| summarize Probes = count() by ip
```

On this data it flagged `167.250.28.185` (11 probes) and `31.171.66.62` (11 probes) and nothing else. I'd rate it High: a script testing writable folders one after another right after a login is almost certainly malware getting ready to drop a file. It maps to ATT&CK T1083 (File and Directory Discovery).

## 5. New detection rule: escaping a router's command line

Routers often give you a limited command line first. These bots try every common way out of it.

```kql
honeypot
| where event == "command"
| where command in ("linuxshell", "ping ;sh", "system", "shell", "enable")
| summarize Escapes = count() by ip
```

It flagged all three bots (9, 9 and 6 escape attempts) and nothing else. On a real Linux server, `enable` or `system` typed as a whole command makes no sense, so this is a reliable sign of an IoT bot. On a real network, I'd scope this rule to SSH and Telnet logins on internet-facing devices, so it doesn't fire on network engineers working on switches.

## 6. New detection rule: payload pulled and piped into a shell

```kql
honeypot
| where event == "command"
| where (command contains "wget" or command contains "tftp") and command contains "|sh"
| summarize Downloads = count() by ip
```

It flagged `31.171.66.62`, the only bot that got as far as trying to download its payload. Downloading a script and piping it straight into `sh` is the moment a device actually gets infected, so I'd rate this one Critical on a real system. It maps to T1105 (Ingress Tool Transfer).
