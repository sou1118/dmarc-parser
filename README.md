# DMARC Parser

This is a simple DMARC parser that reads a DMARC record from a file and returns a dictionary with the parsed values.

## Usage

```shell
$ cargo run

Message 1
Organization: internal.kattyan.dev
Date Range: 1724544000 to 1724630399
Header From: kattyan.dev
Source IP: 192.168.1.1
Count: 1
DKIM Result: Fail
DKIM Domain:
SPF Result: Fail
```
