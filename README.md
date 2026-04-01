# Custom VPN implementation

This repository contains a simple client/server prototype that forwards web requests through an encrypted tunnel.

## Structure

- `server/`: VPN server (Python)
- `client/`: VPN client (Python)
- `scripts/`: helper scripts (e.g., key generation)

## Quick start

1. Create a virtual environment and install dependencies you use (e.g. `cryptography`, `requests`).
2. Start the server:
   - `python server/server.py`
3. Run the client:
   - `python client/client.py`

If you change encryption keys or configuration, ensure client and server match.
