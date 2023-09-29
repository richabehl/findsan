import argparse
import termcolor
import socket
import sys
import ssl
import queue
import tldextract

def tldExt(name):
    return tldextract.extract(name).registered_domain

def find_sans(domains, san_type, output_file):
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

    socket.setdefaulttimeout(5)

    q = queue.Queue()
    printed = set()
    completed = set()
    for domain in finalset:
        q.put(domain)

    while not q.empty():
        try:
            hostname = q.get()
            if san_type == "same":
                if hostname not in printed and hostname not in finalset and any(hostname.endswith(d) for d in additional_parent_domains):
                    print(termcolor.colored(hostname, color='green', attrs=['bold']))
                    nothing_found_flag = False
                    printed.add(hostname)
            elif san_type == "all":
                if hostname not in printed and hostname not in finalset:
                    print(termcolor.colored(hostname, color='green', attrs=['bold']))
                    nothing_found_flag = False
                    printed.add(hostname)

            if hostname not in completed:
                completed.add(hostname)
                try:
                    # Check both port 443 and 80
                    for port in [443, 80]:
                        with socket.create_connection((hostname, port)) as sock:
                            with context.wrap_socket(sock, server_hostname=hostname, ) as ssock:
                                for (k, v) in ssock.getpeercert()['subjectAltName']:
                                    if v not in q.queue and v.startswith("*.") and v.lstrip('*.') not in finalset:
                                        q.put(v.lstrip('*.'))
                                    elif v not in q.queue and v not in finalset:
                                        q.put(v.lstrip('*.'))
                except (socket.gaierror, socket.timeout, ssl.SSLCertVerificationError, ConnectionRefusedError,
                        ssl.SSLError, OSError):
                    pass
        except KeyboardInterrupt:
            print(termcolor.colored("\nKeyboard Interrupt. Exiting...\n", color='red', attrs=['bold']))
            sys.exit(1)

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
    find_sans(domains, san_type, args.output)