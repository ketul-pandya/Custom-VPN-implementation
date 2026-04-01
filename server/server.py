import socket
import threading
import requests
from cryptography.fernet import Fernet

# --- Configuration ---
LISTEN_IP = '127.0.0.1'  # Listen on all available network interfaces
LISTEN_PORT = 4433
SHARED_SECRET_KEY = b'O0gwAWlOpoEmQIlFn51lC357JZ78jI02lj73jQMQVMU=' 
BUFFER_SIZE = 4096
# --- End Configuration ---

# Initialize encryption
try:
    cipher_suite = Fernet(SHARED_SECRET_KEY)
    print("Encryption cipher initialized successfully.")
except Exception as e:
    print(f"[-] Failed to initialize cipher. Invalid key? Error: {e}")
    exit(1)

def handle_client(client_socket):
    """Handles a single client connection."""
    print("[+] New client connection.")
    try:
        while True:
            # 1. Receive encrypted data from client
            encrypted_request = client_socket.recv(BUFFER_SIZE)
            if not encrypted_request:
                print("[-] Client disconnected (received empty data).")
                break # Connection closed by client

            # 2. Decrypt the request
            try:
                decrypted_request = cipher_suite.decrypt(encrypted_request)
                print(f"[>] Received {len(decrypted_request)} decrypted bytes.")
                # The decrypted data should be the target URL
                target_url = decrypted_request.decode('utf-8')
                print(f"[*] Client requested URL: {target_url}")
            except Exception as e:
                print(f"[-] Decryption failed or invalid data received: {e}")
                
                break

            # 3. Make the actual web request
            try:
                print(f"[*] Forwarding request to {target_url}...")
                # Use requests library to handle HTTP/HTTPS, redirects, etc.
                # Sending a standard User-Agent to look like a normal browser
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
                # Allow redirects, verify SSL certificates
                response = requests.get(target_url, headers=headers, timeout=15, stream=True, allow_redirects=True, verify=True)
                response.raise_for_status() # Raise exception for bad status codes (4xx or 5xx)

                # Reading the response content
                # We read in chunks in case of large files
                response_content = b""
                for chunk in response.iter_content(chunk_size=BUFFER_SIZE):
                    response_content += chunk

                print(f"[<] Received {len(response_content)} bytes from target server.")

            except requests.exceptions.RequestException as e:
                print(f"[-] Failed to fetch URL {target_url}: {e}")
                # Sending an error message back 
                response_content = f"Error fetching URL: {e}".encode('utf-8')
            except Exception as e:
                print(f"[-] An unexpected error occurred during request: {e}")
                response_content = f"Unexpected server error: {e}".encode('utf-8')


            # 4. Encrypt the response
            try:
                encrypted_response = cipher_suite.encrypt(response_content)
                print(f"[<] Sending {len(encrypted_response)} encrypted bytes back to client.")
            except Exception as e:
                 print(f"[-] Encryption failed before sending: {e}")
                 break 

            # 5. Send encrypted response back to client
            try:
                client_socket.sendall(encrypted_response)
            except socket.error as e:
                print(f"[-] Socket error while sending to client: {e}")
                break

    except socket.error as e:
        print(f"[-] Socket error during client handling: {e}")
    except Exception as e:
        print(f"[-] Unexpected error in handle_client: {e}")
    finally:
        print("[-] Closing client socket.")
        client_socket.close()

def start_server():
    """Starts the listening server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow reusing the address quickly after restarting the script
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((LISTEN_IP, LISTEN_PORT))
        server.listen(5) # Allowing up to 5 queued connections for this demonstration 
        print(f"[*] Listening on {LISTEN_IP}:{LISTEN_PORT}")
    except socket.error as e:
        print(f"[-] Failed to bind or listen on {LISTEN_IP}:{LISTEN_PORT}. Error: {e}")
        print("    Check if the port is already in use or if you have permissions.")
        return
    except Exception as e:
        print(f"[-] Unexpected error during server setup: {e}")
        return

    while True:
        try:
            client_sock, addr = server.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
            # Start a new thread to handle this client connection
            client_handler = threading.Thread(target=handle_client, args=(client_sock,))
            client_handler.daemon = True # Allows main program to exit even if threads are running
            client_handler.start()
        except KeyboardInterrupt:
            print("\n[*] Server shutting down.")
            break
        except Exception as e:
            print(f"[-] Error accepting connections: {e}")

    server.close()
    print("[*] Server socket closed.")

if __name__ == '__main__':
    start_server()
