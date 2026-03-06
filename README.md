# Hermes

<p align="center">
  <img alt="Hermes Logo" src="agent_icons/hermes.svg" height="30%" width="30%">
</p>

Hermes is a lightweight Linux agent written in Python, designed for Mythic 3.0 and newer. Named after Hermes, messenger of the gods — built for speed and discretion.

## Features

- Linux support
- SOCKS5 proxy support for pivoting and lateral movement
- Encrypted Key Exchange (EKE) with RSA-4096 + AES-256-CBC + HMAC-SHA256
- AESPSK support (pre-shared key, no key exchange required)
- 24 built-in commands covering:
  - Reconnaissance (`whoami`, `ps`, `netstat`, `ifconfig`, `systeminfo`, `env`)
  - File operations (`ls`, `cat`, `cp`, `mv`, `rm`, `mkdir`, `chmod`, `chown`, `find`, `grep`)
  - File transfer (`upload`, `download`)
  - Execution (`shell`)
  - Agent control (`sleep`, `exit`, `cd`)

## Installation

1.) Install Mythic from [here](https://github.com/its-a-feature/Mythic)

2.) From the Mythic install directory, run the following command:

```bash
./mythic-cli install github https://github.com/0xbbuddha/hermes
```

## Supported C2 Profiles

### HTTP

Hermes communicates over the default HTTP profile used by Mythic. All taskings and responses are done via POST requests.

> **Note:** The GET URI parameter is unused — only POST is supported.

## SOCKS5

Hermes supports SOCKS5 proxying through the C2 channel, allowing operators to reach internal network resources via the compromised host.

Start the proxy from the Mythic UI (use a port in the `7000-7010` range exposed by Mythic by default):

```
socks start 7001
```

Use `proxychains` or any SOCKS5-compatible tool on your C2 server:

```bash
proxychains nmap -sT 192.168.1.0/24
curl --socks5 127.0.0.1:7001 http://192.168.1.50/
proxychains xfreerdp /v:192.168.1.10 /u:Administrator
```

Stop the proxy:

```
socks stop 7001
```

> **Note:** SOCKS5 traffic is relayed through the agent's C2 polling loop. A lower sleep interval improves proxy responsiveness.

## Opsec Considerations

### Python Dependency

Hermes is a Python agent and requires Python 3.8+ to be present on the target system. This may increase the detection surface compared to a compiled binary.

### Build Formats

| Format              | Description                                                    |
|---------------------|----------------------------------------------------------------|
| Python script (`.py`) | Minimal footprint, requires Python on target                 |
| Directory bundle    | Self-contained with dependencies, easier to deploy            |

### Sleep Interval

The default sleep interval directly impacts both stealth and performance. A high sleep interval reduces network noise but degrades SOCKS5 proxy throughput. Tune according to your operational requirements.

## Credit

- [@0xbbuddha](https://github.com/0xbbuddha) — Author

## Known Issues

### Linux Only

Hermes is built exclusively for Linux targets. Windows and macOS are not supported.

### SOCKS5 Latency

Because SOCKS5 traffic is relayed through the agent's HTTP polling loop, latency is directly tied to the sleep interval. Real-time protocols (e.g. RDP, interactive shells) may experience degraded performance at higher sleep values.
