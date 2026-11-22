# AD Wazuh API readiness — V3.9.1

After `fleet evidence install --apply --confirm`, the manager service may be active before its HTTPS API on 127.0.0.1:55000 is listening. This is a timing condition, not proof that the AD Windows executor is misconfigured.

## On GCP

```bash
aegismesh-soar ad doctor
```

If the port is not listening and the Wazuh manager configuration is valid, explicitly authorize one service restart:

```bash
aegismesh-soar ad recover --confirm
aegismesh-soar ad doctor
aegismesh-soar ad probe --confirm
```

`ad recover` checks `wazuh-analysisd -t` first, refuses non-loopback API endpoints, never prints API credentials, and only restarts the existing `wazuh-manager.service`. It does not reinstall Wazuh, change system configuration, modify PostgreSQL, or disable AD accounts. On persistent failure check `journalctl -u wazuh-manager -n 50 --no-pager` and `/var/ossec/logs/api.log`.

The probe waits for API readiness, sends only one Wazuh Active Response request, and requires actual agent 006 proof (the API acknowledgement is not proof of remote execution).

After a **verified** probe, configure AD using `aegismesh-soar ad enable --agent-id 006 --domain ad.ikom.mg --confirm`, then inspect `aegismesh-soar ad status` before enrolling any laboratory account.

The `fleet evidence install --apply --confirm` command now waits for the local API listening socket after a Wazuh manager restart. It reports a distinct API-readiness error, retaining otherwise valid installed rules instead of rolling back and restarting the manager again. This does not replace authenticated TLS verification by `ad probe`.
