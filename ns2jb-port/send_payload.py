#!/usr/bin/env python3
"""Send a JS payload to the CivSwitch Remote JS Loader and print streamed logs."""
import socket
import sys

TIMEOUT = 120


def send(host, port, code):
    s = socket.create_connection((host, port), timeout=8)
    s.sendall(code.encode())
    s.shutdown(socket.SHUT_WR)
    s.settimeout(TIMEOUT)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.close()
    return data.decode("utf-8", "replace")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "<CONSOLE_IP>"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9026
    path = sys.argv[3] if len(sys.argv) > 3 else "recon.js"
    code = open(path, encoding="utf-8").read()
    print(send(host, port, code))
