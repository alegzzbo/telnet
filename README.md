# 📡 Telnet Client (Advanced)

<p align="center">
  <b>Powerful telnet client with automation, encryption and escape mode</b><br>
  <b>Мощный telnet-клиент с автоматизацией, шифрованием и escape-режимом</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.20+-00ADD8?logo=go">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos-blue">
  <img src="https://img.shields.io/badge/license-MIT-green">
</p>

---

## 🧾 Table of Contents

- [⚡ Quick Start](#-quick-start)
- [🚀 Features](#-features)
- [⚙️ Configuration](#️-configuration-telnetjson)
- [🤖 Automation (on_connect)](#-automation-on_connect)
- [🎨 Colors](#-colors)
- [🔐 Secrets](#-secrets)
- [⚡ Keepalive](#-keepalive)
- [⎋ Escape Mode](#-escape-mode)
- [🌍 Examples](#-examples-real-world)

---

# ⚡ Quick Start

```bash
go mod tidy
go build -o telnet
./telnet example.com
```

---

# 🚀 Features

- 🔐 AES encryption + OS keyring
- 🎨 Regex-based colored output
- ⚡ Keepalive (anti-idle)
- 🤖 Expect-like automation
- ✍️ Built-in editor
- ⎋ Escape mode (Ctrl+])

---

# ⚙️ Configuration (`telnet.json`)

Located near binary.

## Example

```json
{
  "defaults": {
    "keepalive": 60,
    "keepalive_type": "space_bs"
  },
  "colors": [
    {
      "pattern": "ERROR",
      "color": "red"
    }
  ],
  "hosts": [
    {
      "alias": "router",
      "host": "192.168.1.1",
      "on_connect": []
    }
  ]
}
```

---

# 🤖 Automation (`on_connect`)

## Commands

| Command | Description |
|--------|------------|
| wait:text | wait for string |
| wait:text:5 | wait with timeout |
| waitre:regex | wait regex |
| command | send command |

---

## Example

```json
"on_connect": [
  "wait:login:",
  "admin",
  "wait:Password:",
  "enc:xxxx",
  "wait:#",
  "terminal length 0"
]
```

---

# 🎨 Colors

## Simple

```json
{
  "pattern": "ERROR",
  "color": "red"
}
```

## Groups (advanced)

```json
{
  "pattern": "(user: )(\\w+)",
  "groups": {
    "1": "yellow",
    "2": "green"
  }
}
```

---

# 🔐 Secrets

```
!secret mypassword
```

→ stored as:

```
enc:BASE64
```

---

# ⚡ Keepalive

| Type | Behavior |
|------|--------|
| space_bs | space + backspace |
| 0x13 | CRLF |
| 0x00 | NULL |

---

# ⎋ Escape Mode

Trigger:

```
CTRL + ]
```

Prompt:

```
telnet>
```

## Commands

- help
- status
- connect
- reconnect
- keepalive
- onconnect
- addhost
- quit

---

# 🌍 Examples (Real-world)

## 🔧 Cisco

```json
{
  "alias": "cisco",
  "host": "10.0.0.1",
  "on_connect": [
    "wait:Username:",
    "admin",
    "wait:Password:",
    "enc:xxxx",
    "wait:#",
    "terminal length 0"
  ]
}
```

---

## 🌐 MikroTik

```json
{
  "alias": "mikrotik",
  "host": "192.168.88.1",
  "on_connect": [
    "wait:Login:",
    "admin",
    "wait:Password:",
    "enc:xxxx",
    "wait:>",
    "/terminal length 0"
  ]
}
```

---

## 🐧 Linux (telnet login)

```json
{
  "alias": "linux",
  "host": "192.168.1.10",
  "on_connect": [
    "wait:login:",
    "root",
    "wait:Password:",
    "enc:xxxx",
    "wait:#"
  ]
}
```

---
