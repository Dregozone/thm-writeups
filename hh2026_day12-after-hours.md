# Hacker Holidays (Day 12) - After hours

## Room details

| Key | Value |
| ---- | ---- |
| Room name | After hours |
| Room link | [https://tryhackme.com/room/hh-afterhours-b090d1f0](https://tryhackme.com/room/hh-afterhours-b090d1f0) |
| Difficulty | Medium |
| Date started | 19/08/2026 |
| Date completed | 19/08/2026 |
| Tags | Forensics, hidden auto executables |


## tl;dr Non-technical explanation
 
Something runs on the machine overnight with nobody logged in, but there is no scheduled task, no service and no registry Run key behind it.
 
Windows has a built-in management system (WMI) that can be told "when X happens, run Y". It runs as SYSTEM, survives reboots, and appears in none of the places an analyst normally checks. Everything it needs is stored in one database file on disk.
 
Pulling readable text out of that file exposed a hidden PowerShell command. That command decodes to a second stage, which references a compressed Windows executable stored in the same file. Nothing is ever downloaded and nothing is written to disk, so network monitoring and file scanning would both come back clean.
 
## Scenario
 
Back-office host at the resort is showing logons in the small hours, long after the night technician has left. Startup, Scheduled Tasks and the registry Run keys are all clean per the briefing. I need to find what is keeping itself alive.
 
## Reconnaissance (What I checked for and why)
 
- With the usual autorun locations ruled out by the briefing, the WMI repository was the obvious next place to look. WMI event subscriptions execute on a trigger, run as SYSTEM, and show up in none of the four locations already excluded.
- The repository lives at `C:\Windows\System32\wbem\Repository\OBJECTS.DATA`. It's a binary format, but consumer command lines survive in it as recoverable text, so `strings` is enough to get a first look.
## The vuln
 
Persistence via **WMI event subscription** — abuse of a legitimate Windows feature rather than an exploited vulnerability. A `CommandLineEventConsumer` holds the command to run, and it fires without any scheduled task, service or Run key existing.
 
The payload is staged inside the repository itself. The consumer holds encoded PowerShell, which pulls a compressed PE out of a second object in the same database. No network fetch, no file dropped to disk.
 
## Identification and remediation steps
 
1. Dump strings from the repository and grep for the consumer class and the usual PowerShell launcher keywords:
```bash
strings OBJECTS.DATA | grep -iE "CommandLineEventConsumer|powershell|bypass|downloadstring"
```
 
2. Take the base64 blob from the consumer command line into CyberChef: **From Base64 → Remove null bytes**. The nulls are there because PowerShell's encoded command is UTF-16LE, so every character decodes with a null after it.
3. Read the decoded stage 1 and look for what it calls. It doesn't reach out to the network — it references a local object named **`HardwareTelemetry`**, so the next stage is in the repository too.
4. Grep for that name with context either side, so the surrounding data comes back rather than just the matching line:
```bash
strings OBJECTS.DATA | grep -C 10 -iE "HardwareTelemetry"
```
 
5. That returns a second, much larger base64 string. Stage 1 showed it was compressed, so in CyberChef: **From Base64 → Raw Inflate**.
6. The output starts with `MZ` and contains "This program cannot be run in DOS mode." — PE header and DOS stub, so it's a Windows executable. Saved it out as a `.exe`.
7. Loaded the executable into the reverse engineering tool provided on the machine and read `main()`, which contained a base64-encoded string. Decoding that gave the flag.
 
### Remediation
 
Remove the subscription properly rather than just the consumer — a WMI event subscription is a triad of `__EventFilter`, consumer and `__FilterToConsumerBinding`, and the binding should go first so nothing is left orphaned. The staged PE object needs removing from the repository too, since killing the subscription stops execution but leaves the payload sitting there.
 
For detection, enable the `Microsoft-Windows-WMI-Activity/Operational` log (Event ID 5861 records permanent subscription creation) and PowerShell Script Block Logging, so the next encoded payload is captured in plaintext rather than needing to be carved out of a database file after the fact.
 
## Lessons learned/Key takeaways
 
**WMI event subscription** - Persistence stored in the WMI repository. Fileless, runs as SYSTEM, survives reboot, and shows in none of the standard autorun locations.
 
**Ruled-out locations are a hint** - When a brief eliminates Startup, Tasks and Run keys, it's pointing at the mechanism that hides from all of them.
 
**Null bytes mean UTF-16** - PowerShell encoded commands are UTF-16LE base64, so decoded output has a null after every character. Same reason `strings -el` finds things plain `strings` misses on Windows artifacts.
 
**`grep -C` on a binary dump** - The matching line is rarely the whole story. Pulling context either side is what surfaced the staged payload sitting next to its name.
 
**`MZ` + "This program cannot be run in DOS mode."** - PE header and DOS stub. Two-second confirmation you're holding a Windows executable rather than more script.
 
**Self-contained staging** - The payload never touched the network or the filesystem. Proxy logs and file-based AV would both come back clean, which is why the artifact-level check was the only thing that would find it.
