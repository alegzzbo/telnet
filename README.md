# 📡 Telnet Client (Advanced)

> 🇬🇧 Advanced Telnet client with automation, encryption and escape mode  
> 🇷🇺 Продвинутый telnet-клиент с автоматизацией, шифрованием и escape-режимом  

---

## 🧾 Table of Contents

- [English](#-english)
- [Русский](#-русский)

---

# 🇬🇧 English

## 🚀 Features

- 🔐 AES encryption + OS keyring
- 🎨 Regex-based colored output
- ⚡ Keepalive (anti-idle)
- 🤖 Expect-like automation (`on_connect`)
- ✍️ Built-in editor
- ⎋ Escape mode (Ctrl+])

---

## ⚡ Installation

```bash
go build -o telnet
```

---

## ▶️ Usage

```bash
./telnet example.com
./telnet example.com 2323
./telnet myalias
```

---

## ⚙️ Configuration (`telnet.json`)

Located near the binary.

### Full example

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
    },
    {
      "pattern": "(user: )(\\w+)",
      "groups": {
        "1": "cyan",
        "2": "green"
      }
    }
  ],
  "hosts": [
    {
      "alias": "prod",
      "host": "10.0.0.1",
      "port": "23",
      "keepalive": 30,
      "keepalive_type": "0x13",
      "on_connect": [
        "wait:login:",
        "admin",
        "wait:Password:",
        "enc:BASE64_ENCRYPTED",
        "wait:#",
        "terminal length 0"
      ]
    }
  ]
}
```

---

## 🔐 Secrets

Use:

```
!secret mypassword
```

It will be stored as:

```
enc:BASE64
```

### Key management

```bash
telnet keys export
telnet keys import
```

---

## 🤖 on_connect automation

Supported commands:

| Command | Description |
|--------|------------|
| `wait:text` | wait for string |
| `wait:text:5` | wait with timeout |
| `waitre:regex` | wait regex |
| `command` | send command |

---

## ⚡ Keepalive

| Type | Behavior |
|------|--------|
| space_bs | space + backspace |
| 0x13 | CRLF |
| 0x00 | NULL |

CLI example:

```bash
./telnet -keepalive 30 -keepalive_type 0x13 host
```

---

## ⎋ Escape Mode

Trigger:

```
CTRL + ]
```

Prompt:

```
telnet>
```

---

### Commands

| Command | Description |
|--------|------------|
| help | show commands |
| status | connection status |
| connect | connect to host |
| close | close connection |
| reconnect | reconnect |
| keepalive | set interval |
| addhost | save host |
| onconnect | manage automation |
| keys | key management |
| resume / c | return to session |
| quit | exit |

---

## ✍️ Built-in Editor

- Ctrl+D → save  
- Ctrl+C → cancel  

Supports arrows, delete, navigation.

---

## 🎨 Colors

Simple:

```json
{
  "pattern": "ERROR",
  "color": "red"
}
```

Advanced (groups):

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

## 📌 Tips

- Use aliases instead of IP
- Store passwords only via `!secret`
- Combine `wait` + commands
- Use color rules for logs

---

# 🇷🇺 Русский

## 🚀 Возможности

- 🔐 AES-шифрование + keyring
- 🎨 Цветной вывод через regex
- ⚡ Keepalive (anti-idle)
- 🤖 Автоматизация (`on_connect`)
- ✍️ Встроенный редактор
- ⎋ Escape mode (Ctrl+])

---

## ⚡ Установка

```bash
go build -o telnet
```

---

## ▶️ Запуск

```bash
./telnet example.com
./telnet example.com 2323
./telnet myalias
```

---

## ⚙️ Конфиг (`telnet.json`)

Файл рядом с бинарником.

### Пример

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
      "alias": "prod",
      "host": "10.0.0.1",
      "on_connect": [
        "wait:login:",
        "admin",
        "wait:Password:",
        "enc:BASE64"
      ]
    }
  ]
}
```

---

## 🔐 Секреты

В редакторе:

```
!secret password
```

→ сохраняется как:

```
enc:BASE64
```

---

## 🤖 on_connect

Команды:

| Команда | Описание |
|--------|--------|
| wait: | ожидание строки |
| wait:text:<timeout> | ожидание строки с таймаутом |
| waitre: | regex |
| команда | отправка |

---

## ⚡ Keepalive

Типы:

| Тип | Поведение |
|-----|--------|
| space_bs | пробел + backspace |
| 0x13 | CRLF |
| 0x00 | NULL |

---

## ⎋ Escape Mode

Активация:

```
CTRL + ]
```

---

### Команды

| Команда | Описание |
|--------|--------|
| help | помощь |
| status | статус |
| connect | подключение |
| close | закрыть |
| reconnect | переподключить |
| keepalive | интервал |
| addhost | сохранить |
| onconnect | команды |
| keys | ключи |
| resume | назад |
| quit | выход |

---

## ✍️ Редактор

- Ctrl+D → сохранить  
- Ctrl+C → отменить  

---

## 📌 Советы

- используй alias
- пароли только через `!secret`
- комбинируй wait + команды
- раскрашивай логи
