<div align="center">
  
<img src="https://raw.githubusercontent.com/ietf-tools/common/main/assets/logos/mail-tlsa-check-exporter.svg" alt="Mail TLSA Check Exporter" height="125" />

[![License](https://img.shields.io/github/license/ietf-tools/mail-tlsa-check-exporter)](https://github.com/ietf-tools/mail-tlsa-check-exporter/blob/main/LICENSE)
[![Node Version](https://img.shields.io/badge/node.js->=23.9-green?logo=node.js&logoColor=white)](#prerequisites)

##### Validate SMTP / IMAP server certificates against a TLSA record as a Prometheus-compatible exporter

</div>

## Prerequisites

- [Node.js](https://nodejs.org/) **v23.9.0** or later

## Install

1. Clone this repo
2. Rename `.env.sample` to `.env`
3. Edit `.env` and replace the values with your own configuration.

## Run

### Manually

```sh
node --env-file=.env index.mjs
```

### As a Service

> The code snippets below assume the files are installed in the `/root/mail_tlsa_check_exporter` directory. Adjust the path below otherwise.

1. Create the service:
  ```sh
  sudo nano /etc/systemd/system/mail_tlsa_check_exporter.service
  ```
  with the following contents:
  ```service
  [Unit]
  Description=MailTLSACheckExporter
  Wants=network-online.target
  After=network-online.target
  
  [Service]
  ExecStart=/usr/bin/node --env-file=.env index.mjs
  WorkingDirectory=/root/mail_tlsa_check_exporter
  Restart=always
  User=root
  Environment=PATH=/usr/bin:/usr/local/bin
  
  [Install]
  WantedBy=multi-user.target
  ```
2. Save and exit, then reload systemd:
  ```sh
  sudo systemctl daemon-reload
  ```
3. Start the service:
  ```sh
  sudo systemctl start mail_tlsa_check_exporter
  ```
4. Make sure the service is starting properly:
  ```sh
  sudo systemctl status mail_tlsa_check_exporter
  ```
5. Enable the service on boot:
  ```sh
  sudo systemctl enable mail_tlsa_check_exporter
  ```


## Prometheus / Grafana Alloy Configuration

Add a scrape target to your Prometheus / Grafana Alloy configuration to the port defined in `.env` (`19309` by default), e.g.:

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
      __address__ = "127.0.0.1:19309",
    },
  ]
  forward_to = [prometheus.remote_write.default.receiver]
}
```
