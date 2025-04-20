# mail-tlsa-check-exporter

Validate SMTP / IMAP server certificates against a TLSA record as a Prometheus-compatible exporter

## Install

1. Clone this repo
2. Rename `.env.sample` to `.env`
3. Edit `.env` and replace the values with your own configuration.

## Run

```sh
node --env-file=.env index.mjs
```