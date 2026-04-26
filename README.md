# Custom VPN Implementation

A secure encrypted VPN tunnel with mutual authentication, digital signatures, and traffic policy enforcement.

## Security Features

| Objective          | Implementation                                                 |
|--------------------|----------------------------------------------------------------|
| **Confidentiality**    | AES-256-GCM encryption on all tunnel traffic                 |
| **Integrity**          | HMAC-SHA256 on every frame + GCM authentication tags         |
| **Authentication**     | Mutual challenge–response handshake with nonces              |
| **Non-repudiation**    | RSA-PSS digital signatures during session establishment      |
| **Access Control**     | IP whitelisting with CIDR support                            |
| **Availability**       | Token-bucket rate limiting, connection caps, idle timeouts   |

## Project Structure

```
├── crypto/                    # Person 1: Protocol + Crypto
│   ├── protocol.py            # Wire protocol: binary framing + message types
│   ├── crypto_utils.py        # AES-GCM, HMAC-SHA256, HKDF key derivation
│   └── test_crypto.py         # Unit tests + test vectors
├── auth/                      # Person 2: Authentication + Signatures
│   ├── handshake.py           # Mutual challenge–response handshake
│   ├── signatures.py          # RSA-PSS sign/verify
│   ├── key_manager.py         # RSA keypair generation/storage/loading
│   └── test_auth.py           # Auth tests (success + failure)
├── client/                    # Person 3: Client proxy
│   ├── client_proxy.py        # Local HTTP/HTTPS proxy entrypoint
│   └── tunnel_client.py       # Encrypted tunnel connection manager
├── server/                    # Person 4: Server + policies
│   ├── server_main.py         # Multi-client server entrypoint
│   ├── forwarder.py           # HTTP/HTTPS forwarding to target sites
│   ├── access_control.py      # IP whitelisting
│   └── rate_limit.py          # Token-bucket rate limiter
├── scripts/                   # Person 5 + utilities
│   ├── generate_keys.py       # RSA keypair generation
│   ├── demo_run.py            # Automated end-to-end demo
│   └── load_test.py           # Rate limiting load test
├── analysis/                  # Wireshark validation
│   ├── capture_guide.md       # Step-by-step Wireshark instructions
│   └── checklist.md           # Requirement → evidence mapping
├── config/
│   ├── server_config.json     # Server configuration
│   └── whitelist.txt          # Allowed client IPs
└── keys/                      # Generated RSA keys (gitignored)
```

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate RSA keys

```bash
python scripts/generate_keys.py
```

This creates `keys/server_private.pem`, `keys/server_public.pem`, `keys/client_private.pem`, `keys/client_public.pem`.

### 3. Start the VPN server

```bash
python -m server.server_main
```

Configuration is loaded from `config/server_config.json`. Override with CLI flags:

```bash
python -m server.server_main --listen-port 4433 --log-level DEBUG
```

### 4. Start the VPN client proxy

```bash
python -m client.client_proxy --server-host 127.0.0.1 --server-port 4433
```

### 5. Configure your browser

Set your browser's HTTP proxy to `127.0.0.1:8888`, then browse normally.

Or use curl:

```bash
curl -x http://127.0.0.1:8888 http://httpbin.org/get
```

### 6. Run the automated demo

```bash
python scripts/demo_run.py
```

## Testing

```bash
# Run all unit tests
python -m pytest crypto/test_crypto.py auth/test_auth.py -v

# Run load test (rate limiting demo)
python scripts/load_test.py --requests 200 --threads 20
```

## Wire Protocol

Every message uses this binary frame format:

```
┌──────────┬──────────┬──────────────┬───────┬──────────────────┬──────────┐
│ 4 bytes  │ 1 byte   │ 16 bytes     │ 12 B  │ variable         │ 32 bytes │
│ total_len│ msg_type │ session_id   │ nonce │ encrypted payload│ HMAC     │
└──────────┴──────────┴──────────────┴───────┴──────────────────┴──────────┘
```

- **Length-prefixed**: handles partial TCP reads/writes correctly
- **HMAC** covers msg_type + session_id + nonce + payload (tamper detection)
- **AES-256-GCM** provides authenticated encryption of the payload

## Handshake Sequence

```
Client                              Server
  │── ClientHello(nonce, ts) ──────────>│
  │                                      │ verify timestamp
  │<── ServerHello(nonce, ts,            │
  │     challenge, RSA signature) ──────│
  │                                      │
  │  verify server signature             │
  │── ClientResponse(challenge_resp,     │
  │     RSA signature) ────────────────>│
  │                                      │ verify client signature
  │<── ServerDone(encrypted_session_key)│
  │                                      │
  [Session established — AES-256-GCM from here]
```

## Configuration

### Server (`config/server_config.json`)

| Key                           | Default | Description                          |
|-------------------------------|---------|--------------------------------------|
| `listen_ip`                   | 0.0.0.0 | Bind address                        |
| `listen_port`                 | 4433    | Tunnel port                         |
| `rate_limit_requests_per_second` | 10   | Per-IP rate limit                   |
| `max_connections_per_ip`      | 5       | Per-IP connection cap               |
| `max_total_connections`       | 50      | Global connection cap               |
| `idle_timeout_seconds`        | 300     | Drop idle connections after N secs  |

### IP Whitelist (`config/whitelist.txt`)

One IP or CIDR range per line. If empty/missing, all IPs are allowed.

## Wireshark Analysis

See `analysis/capture_guide.md` for detailed capture procedures covering:
- Baseline (plaintext) vs encrypted tunnel traffic
- Authentication handshake visibility
- Tampered frame detection
- Rate limiting under load
- IP whitelist blocking
