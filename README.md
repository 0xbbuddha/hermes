# Hermes

<p align="center">
  <img alt="Hermes Logo" src="agent_icons/caduceus.svg" height="30%" width="30%">
</p>

Mythic C2 agent **Linux-only** written in Python. Named after Hermes, messenger god of Greek mythology.

## Installation

From the Mythic installation directory:

```bash
./mythic-cli install folder /path/to/hermes
# or
sudo -E ./mythic-cli install github https://github.com/0xbbuddha/hermes
```

Then restart Mythic.

## Prerequisites

- **Target OS**: Linux only (not Windows, not macOS)
- **Python**: 3.8+ on target for script execution, or PyInstaller binary

## Features

- Check-in and tasking via HTTP profile (EKE + AES)
- 18 built-in commands for reconnaissance and file operations
- Output: Python script `.py` or deployable directory

## Commands

| Command   | Description                          |
|-----------|--------------------------------------|
| shell     | Execute a shell command              |
| ls        | List a directory                     |
| pwd       | Current working directory            |
| cat       | Display a file                       |
| cd        | Change directory                     |
| download  | Download a file from target          |
| upload    | Upload a file to target              |
| sleep     | Callback interval (seconds)          |
| exit      | Exit the agent                       |
| whoami    | User / hostname                      |
| ps        | List running processes               |
| netstat   | Network connections and ports        |
| ifconfig  | Network interface configuration      |
| env       | Environment variables                |
| rm        | Remove file or directory             |
| mkdir     | Create directory                     |
| cp        | Copy file                            |
| mv        | Move or rename file                  |

## C2

Supported profile: **HTTP** (Mythic EKE + AES compatible).

## License

MIT License — see [COPYING](COPYING).
