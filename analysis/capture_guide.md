# Wireshark Traffic Capture & Analysis Guide

## Prerequisites

- [Wireshark](https://www.wireshark.org/download.html) installed
- VPN server + client running (see `scripts/demo_run.py`)
- Npcap (Windows) or libpcap (Linux) for loopback capture

## Capture Procedures

### 1. Baseline Capture (No Tunnel — Plaintext)

To show what traffic looks like **without** the VPN:

1. Open Wireshark → select **Loopback** (or `lo`) adapter
2. Start capture
3. Make a direct HTTP request:
   ```bash
   curl http://httpbin.org/get
   ```
4. Stop capture
5. Filter: `http` or `tcp.port == 80`
6. **Observation**: You can see the full URL, HTTP headers, and response body in plaintext

Save as: `baseline_plaintext.pcapng`

### 2. Encrypted Tunnel Capture

1. Open Wireshark → select **Loopback** adapter
2. Set capture filter: `port 4433` (VPN tunnel port)
3. Start capture
4. Run the VPN server and client:
   ```bash
   python -m server.server_main &
   python -m client.client_proxy &
   ```
5. Make requests through the proxy:
   ```bash
   # Note: In Windows PowerShell, use `curl.exe` instead of `curl`
   curl -x http://127.0.0.1:8888 http://httpbin.org/get
   ```
6. Stop capture
7. **Observation**: All traffic on port 4433 is encrypted binary data. No HTTP headers, URLs, or content are readable

Save as: `tunnel_encrypted.pcapng`

### 3. Authentication Handshake Capture

1. Open Wireshark → filter: `port 4433`
2. Start capture
3. With the server already running, start the client (do not make any HTTP requests yet):
   ```bash
   python -m client.client_proxy
   ```
4. Stop capture after connection is established
5. **Observation**: First ~4 TCP segments show the handshake:
   - ClientHello, ServerHello, ClientResponse, ServerDone
   - All are framed binary data — no keys or secrets visible on the wire
   - The handshake carries digital signatures but these are opaque in Wireshark

Save as: `handshake_auth.pcapng`

### 4. Failed Authentication Capture

1. Generate a **second** (wrong) keypair:
   ```bash
   mkdir keys_wrong
   python -c "
   from auth.key_manager import generate_rsa_keypair, save_private_key, save_public_key
   priv, pub = generate_rsa_keypair()
   save_private_key(priv, 'keys_wrong/client_private.pem')
   save_public_key(pub, 'keys_wrong/client_public.pem')
   "
   ```
2. Start Wireshark on port 4433
3. Start client with wrong key:
   ```bash
   python -m client.client_proxy --client-key keys_wrong/client_private.pem
   ```
4. **Observation**: Connection terminates after handshake (ERROR frame sent), no data is proxied

Save as: `auth_failed.pcapng`

### 5. Integrity / Tamper Detection

This is shown via the unit tests:
```bash
python -m pytest crypto/test_crypto.py::TestFraming::test_hmac_tamper_detected -v
```

Server logs will show `FRAME_ERROR` / `HMAC verification failed` when tampered frames are received.

### 6. Rate Limiting Under Load

1. Start Wireshark on port 4433
2. Start server + client normally
3. Run load test:
   ```bash
   python scripts/load_test.py --requests 200 --threads 20
   ```
4. **Observation**: After initial burst, server sends ERROR frames with "Rate limit exceeded"
5. Check server logs for `RATE_LIMITED` entries

Save as: `rate_limiting.pcapng`

### 7. IP Whitelist Blocking

1. Edit `config/whitelist.txt` to only allow a non-matching IP:
   ```
   # Remove 127.0.0.1 and add only:
   203.0.113.1
   ```
2. Restart server
3. Try to connect client → connection is immediately closed
4. Server logs show: `AUTH_DENIED  ip=127.0.0.1  reason=whitelist`

## Wireshark Display Filters

| What                    | Filter                                      |
| ----------------------- | ------------------------------------------- |
| All tunnel traffic      | `tcp.port == 4433`                          |
| Baseline HTTP           | `http`                                      |
| Handshake only          | `tcp.port == 4433 && tcp.len > 0`           |
| Large payloads          | `tcp.port == 4433 && tcp.len > 1000`        |
| Connection resets       | `tcp.flags.reset == 1 && tcp.port == 4433`  |

## Expected Results Summary

| Requirement        | What to look for                                     |
| ------------------ | ---------------------------------------------------- |
| Confidentiality    | No readable HTTP content in tunnel traffic           |
| Integrity          | Tampered frame → HMAC error → connection closed      |
| Authentication     | Handshake with signed messages before any data       |
| Non-repudiation    | RSA-PSS signatures in handshake (opaque on wire)     |
| Access control     | Whitelisted IP: allowed; others: rejected in logs    |
| Availability       | Rate limiting: ERROR frames + log entries under load |
