# Reproducible Synthetic Linux IR Exercise

Use `aegisir demo` and copy the generated case ID. The synthetic case uses fabricated data only:

- `www-data` listed with `sudo` supplementary group.
- A pretend running executable under `/tmp/update-service`.
- A cron entry executing `/tmp/update-service` every five minutes.
- A root authorized-key fingerprint that is explicitly marked synthetic.
- A listener on port 4444 in simulated `/proc/net/tcp` output.
- A mocked readiness gap for NTP verification.

These are **training indicators**, not confirmed evidence of compromise, and are NOT present on your machine just because the demo report lists them.

```bash
aegisir demo
aegisir show IR-DEMO-ID
aegisir findings IR-DEMO-ID
aegisir inspect IR-DEMO-ID FD-ID
aegisir decide IR-DEMO-ID FD-ID --choice defer --reason 'Synthetic alert pending simulated owner response'
aegisir checklist IR-DEMO-ID
aegisir verify IR-DEMO-ID
aegisir report IR-DEMO-ID --output training-report.md
```

Try `aegisir act IR-DEMO-ID FD-ID --live`: it must fail (missing explicit lab flag, interactive TTY and synthetic case restriction). **Do not** set the lab action flag to bypass this demonstration test.
