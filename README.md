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

## Prometheus / Grafana Alloy Configuration

Add a scrape target to your Prometheus / Grafana Alloy configuration to the port defined in `.env` (`9309` by default), e.g.:

```river
logging {
  level = "warn"
}

prometheus.remote_write "default" {
  endpoint {
    url = "http://your-prometheus-server/api/v1/push"
  }
}

prometheus.scrape "default" {
  targets = [
    {
      job         = "mail-tlsa-check-exporter",
      __address__ = "127.0.0.1:9309",
    },
  ]
  forward_to = [prometheus.remote_write.default.receiver]
}
```