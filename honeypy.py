#libraries
import argparse
from ssh_honeypot import *

#parse arguments
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--address', type=str, required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-u', '--username', type=str)
    parser.add_argument('-pw', '--password', type=str)

    parser.add_argument('-s', '--ssh', action='store_true')
    parser.add_argument('-w', '--http', action='store_true')
    args = parser.parse_args()
    try:
        if args.ssh:
            print("[-] Running SSH Honeypot...")
            honeypot(args.address, args.port, args.username, args.password)
            if not args.username:
                username = None
            if not args.password:
                password = None
        elif args.http:
            print("[-] Running HTTP Honeypot...")
            # http_honeypot(args.address, args.port) # We would implement a similar function for the HTTP honeypot, which would listen for incoming HTTP requests and log them accordingly.
            pass
        else:
            print("[!] Choose a honypot to run: --ssh for SSH honeypot or --http for HTTP honeypot")
    except:
        print("\n Exiting HONEYPY...\n")