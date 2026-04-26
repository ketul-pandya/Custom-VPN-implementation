# Requirement Verification Checklist

Map of project objectives → evidence and test results.

## Confidentiality

- [ ] **AES-256-GCM encryption** implemented in `crypto/crypto_utils.py`
- [ ] **Every data frame is encrypted** — verified by `crypto/test_crypto.py::TestAESGCM`
- [ ] **Wireshark capture** shows no readable HTTP content/URLs in tunnel traffic
  - pcap: `tunnel_encrypted.pcapng`
  - Screenshot: _attach comparison of plaintext vs encrypted_
- [ ] **Key derivation** via HKDF ensures unique enc/mac keys per session

## Integrity

- [ ] **HMAC-SHA256** on every frame — implemented in `crypto/protocol.py`
- [ ] **Tamper detected** — verified by `crypto/test_crypto.py::TestFraming::test_hmac_tamper_detected`
- [ ] **AES-GCM authentication tag** provides payload-level integrity
- [ ] **Server logs** show `FRAME_ERROR` when tampered frame received
- [ ] **Wireshark evidence**: tampered packet → connection closed (TCP RST)

## Authentication (Mutual)

- [ ] **Challenge–response** handshake with nonces — `auth/handshake.py`
- [ ] **Both sides authenticate**: client proves identity to server and vice versa
- [ ] **Nonce + timestamp** prevents replay attacks
- [ ] **Wrong key → handshake fails** — verified by `auth/test_auth.py::TestHandshake::test_wrong_server_key_fails`
- [ ] **Server logs** show `HANDSHAKE_FAILED` for invalid credentials
- [ ] **Wireshark capture** shows handshake message exchange before any data

## Non-Repudiation (Digital Signatures)

- [ ] **RSA-PSS signatures** during handshake — `auth/signatures.py`
- [ ] **Both sides sign** the handshake transcript (nonce_c ‖ nonce_s)
- [ ] **Signature verification** on both ends before proceeding
- [ ] **Signed data can be audited** — handshake messages contain verifiable signatures
- [ ] **Test coverage** — `auth/test_auth.py::TestSignatures`

## Access Control (IP Whitelisting)

- [ ] **Whitelist file** at `config/whitelist.txt` — CIDR support
- [ ] **Blocked IPs** cannot establish session — `server/access_control.py`
- [ ] **Server logs** show `AUTH_DENIED  reason=whitelist` for blocked IPs
- [ ] **Demo**: remove 127.0.0.1 from whitelist → client cannot connect
- [ ] **Hot-reload** supported (no server restart needed)

## Availability (Rate Limiting + DoS Protection)

- [ ] **Token-bucket rate limiter** — `server/rate_limit.py`
- [ ] **Per-IP request rate limiting** (default 10 req/s, burst 20)
- [ ] **Per-IP connection cap** (default 5)
- [ ] **Global connection cap** (default 50)
- [ ] **Idle timeout** for inactive connections (default 300s)
- [ ] **Load test script** — `scripts/load_test.py`
- [ ] **Server logs** show `RATE_LIMITED` and `CONN_REJECTED` events
- [ ] **Wireshark capture** shows rate-limited responses under load

## Traffic Analysis (Wireshark)

- [ ] **Baseline pcap** — plaintext HTTP traffic (no tunnel)
- [ ] **Encrypted pcap** — tunnel traffic (no readable content)
- [ ] **Auth handshake pcap** — shows message exchange
- [ ] **Failed auth pcap** — connection rejected
- [ ] **Rate limiting pcap** — throttling visible
- [ ] **Comparison screenshots** — side by side plaintext vs encrypted
- [ ] **Capture guide** — `analysis/capture_guide.md`

## Demo Checklist (5–10 min live demo)

1. [ ] Show `config/server_config.json` and `config/whitelist.txt`
2. [ ] Run `python scripts/generate_keys.py` — show key generation
3. [ ] Start server: `python -m server.server_main`
4. [ ] Start client: `python -m client.client_proxy`
5. [ ] Show handshake in server logs (mutual auth + signatures)
6. [ ] Make request: `curl -x http://127.0.0.1:8888 http://httpbin.org/get`
7. [ ] Show Wireshark: encrypted traffic vs baseline
8. [ ] Run `python scripts/load_test.py` — show rate limiting in logs
9. [ ] Edit whitelist to block client IP → show rejected connection
10. [ ] Run tamper detection test: `python -m pytest crypto/test_crypto.py::TestFraming::test_hmac_tamper_detected -v`
