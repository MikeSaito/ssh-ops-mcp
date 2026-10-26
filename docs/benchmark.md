# SSH latency measurements

Measured on 2026-10-26 using local Docker Linux fixtures, Node.js 22.23.1 and 20 sequential samples per group. These numbers include local scheduling and helper startup; they do not predict Internet latency. No production servers were contacted.

| Server | Measurement | Median, ms | p95, ms |
| --- | --- | ---: | ---: |
| OpenSSH | Connection setup | 116.11 | 120.16 |
| OpenSSH | Helper, separate connection | 208.66 | 238.72 |
| OpenSSH | Helper, retained transport prototype | 158.54 | 163.08 |
| OpenSSH | MCP, separate connection | 211.31 | 247.89 |
| Dropbear | Connection setup | 148.14 | 152.39 |
| Dropbear | Helper, separate connection | 275.51 | 281.71 |
| Dropbear | Helper, retained transport prototype | 127.57 | 138.96 |
| Dropbear | MCP, separate connection | 278.28 | 289.34 |

The prototype shows that transport reuse can reduce helper latency. It is not a production MCP pool and does not include pooled MCP audit/queue overhead. Before enabling pooling, validate concurrent channel leases, cancellation isolation, dead-connection eviction, bounded sessions/memory, agent/socket changes and uncertain-command outcomes. There is no automatic replay of commands. Production keeps separate SSH connections for each call.

Run `npm run bench:ssh` to reproduce with generated fixture keys. Connection timing is also split into configuration, TCP, SSH handshake and authentication in the JSON result. No credentials or commands are included in the benchmark report.
