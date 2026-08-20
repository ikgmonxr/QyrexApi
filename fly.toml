# QrexApi — Fly.io
app = "qyrexapi"
primary_region = "iad"

[build]

[env]
  PORT = "8080"
  NODE_ENV = "production"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 0
  processes = ["app"]

  [[http_service.checks]]
    interval = "15s"
    timeout = "5s"
    grace_period = "30s"
    method = "GET"
    path = "/api/health"

[[vm]]
  memory = "512mb"
  cpu_kind = "shared"
  cpus = 1
