import argparse
import termcolor
import socket
import sys
import ssl
import queue
import tldextract
import threading
from tqdm import tqdm  # Import tqdm for progress bar

def tldExt(name):
    return tldextract.extract(name).registered_domain

def find_sans(domains, san_type, output_file, max_retries, timeout, custom_port, verbose):
    finalset = set(domains)
    additional_parent_domains = set()
    for domain in finalset:
        additional_parent_domains.add(tldExt(domain))

    finalset = finalset.union(additional_parent_domains)

    print(termcolor.colored('_' * 60, color='white', attrs=['bold']))
    print(termcolor.colored("\nFinding subdomains using Subject Alternative Names(SANs)...\n", color='yellow', attrs=['bold']))
    nothing_found_flag = True
    context = ssl.create_default_context()
    context.check_hostname = False

    socket.setdefaulttimeout(timeout)

    q = queue.Queue()
    printed = set()
    completed = set()
    lock = threading.Lock()

    def print_result(hostname):
        nonlocal nothing_found_flag
        if hostname not in printed and hostname not in finalset:
            with lock:
                print(termcolor.colored(hostname, color='green', attrs=['bold']))
                nothing_found_flag = False
                printed.add(hostname)

    for domain in finalset:
        q.put(domain)

    def check_san(hostname):
        try:
            # Check both custom_port and 443
            for port in [custom_port, 443]:
                with socket.create_connection((hostname, port)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        for (k, v) in ssock.getpeercert()['subjectAltName']:
                            if san_type == "same":
                                if v.endswith(tuple(additional_parent_domains)):
                                    print_result(v)
                            elif san_type == "all":
                                print_result(v)

                            if v not in q.queue and v.startswith("*.") and v.lstrip('*.') not in finalset:
                                q.put(v.lstrip('*.'))
                            elif v not in q.queue and v not in finalset:
                                q.put(v.lstrip('*.'))
        except (socket.gaierror, socket.timeout, ssl.SSLCertVerificationError, ConnectionRefusedError,
                ssl.SSLError, OSError):
            pass

    def process_domain():
        while not q.empty():
            try:
                hostname = q.get()
                if san_type == "same":
                    if hostname.endswith(tuple(additional_parent_domains)):
                        print_result(hostname)
                elif san_type == "all":
                    print_result(hostname)

                if hostname not in completed:
                    completed.add(hostname)
                    for _ in range(max_retries):
                        check_san(hostname)
            except KeyboardInterrupt:
                print(termcolor.colored("\nKeyboard Interrupt. Exiting...\n", color='red', attrs=['bold']))
                sys.exit(1)

    threads = []
    for _ in range(5):  # Number of threads to use
        t = threading.Thread(target=process_domain)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if nothing_found_flag:
        print(termcolor.colored("No SANs found.", color='green', attrs=['bold']))

    if output_file:
        with open(output_file, 'w') as f:
            for item in printed:
                f.write("%s\n" % item)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find subdomains using Subject Alternative Names (SANs)")
    parser.add_argument("-u", "--url", help="Single URL to check")
    parser.add_argument("-l", "--list", help="Path to a file containing a list of URLs")
    parser.add_argument("-o", "--output", help="Path to save the plain output")
    parser.add_argument("-a", "--all", action="store_true", help="Enable 'all' mode")
    parser.add_argument("-s", "--same", action="store_true", help="Enable 'same' mode")
    parser.add_argument("--max-retries", type=int, default=3, help="Maximum retries for failed connections")
    parser.add_argument("--timeout", type=float, default=5, help="Socket timeout in seconds")
    parser.add_argument("--custom-port", type=int, default=443, help="Custom port for checking SSL certificates")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose mode")

    args = parser.parse_args()

    if not args.url and not args.list:
        print("You must provide either a single URL (-u) or a list of URLs (-l).")
        sys.exit(1)

    if args.url:
        domains = [args.url]
    else:
        try:
            with open(args.list, 'r') as d:
                domains = d.read().strip().split()
        except FileNotFoundError:
            print("File Not Exist..")
            sys.exit(1)

    san_type = "all" if args.all else "same"

    # Initialize tqdm for progress bar
    with tqdm(total=len(domains), desc="Processing Domains", unit="domains") as pbar:
        find_sans(domains, san_type, args.output, args.max_retries, args.timeout, args.custom_port, args.verbose)
        pbar.update(len(domains))
