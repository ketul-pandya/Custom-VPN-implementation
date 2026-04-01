import socket
import sys

# --- Configuration ---
# IMPORTANT: Replace these with the details from your ngrok output!
NGROK_HOST = '0.tcp.in.ngrok.io' # e.g., '0.tcp.ngrok.io'
NGROK_PORT = 17570                             # e.g., 10124 (must be an integer)
# --- End Configuration ---

BUFFER_SIZE = 1024
MESSAGE_TO_SEND = "Hello ngrok tunnel!"

print("--- Simple TCP Client ---")

# Basic validation
if 'REPLACE_WITH_NGROK_HOSTNAME' in NGROK_HOST or NGROK_PORT == 0:
    print("[!] ERROR: Please edit simple_client.py and replace NGROK_HOST and NGROK_PORT")
    print("         with the actual hostname and port provided by ngrok.")
    sys.exit(1)

client_socket = None # Initialize

try:
    print(f"[*] Attempting to connect to {NGROK_HOST}:{NGROK_PORT}...")

    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Set a timeout for connection attempt (e.g., 10 seconds)
    client_socket.settimeout(10)

    # Connect the socket to the server's public ngrok address
    client_socket.connect((NGROK_HOST, NGROK_PORT))

    # Set timeout for send/receive after connection
    client_socket.settimeout(10)

    print(f"[+] Connected successfully to {NGROK_HOST}:{NGROK_PORT}")

    # Send data
    print(f"[>] Sending message: '{MESSAGE_TO_SEND}'")
    client_socket.sendall(MESSAGE_TO_SEND.encode('utf-8'))

    # Look for the response
    print("[<] Waiting for server response...")
    data = client_socket.recv(BUFFER_SIZE)

    if data:
        response = data.decode('utf-8')
        print(f"[<] Received response: '{response}'")
    else:
        print("[!] Received no response from server.")

except socket.timeout:
    print(f"[!] Connection or operation timed out connecting to {NGROK_HOST}:{NGROK_PORT}.")
except socket.error as e:
    print(f"[!] Socket Error connecting to {NGROK_HOST}:{NGROK_PORT}: {e}")
    print("    Check if the hostname/port are correct and if ngrok/server are running.")
except Exception as e:
    print(f"[!] An unexpected error occurred: {e}")
finally:
    if client_socket:
        print("[-] Closing client socket.")
        client_socket.close()

print("--- Client finished ---")