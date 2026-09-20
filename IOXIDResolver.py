#!/usr/bin/env python3
"""Remotely enumerate a host's network interfaces via the DCOM OXID resolver.

Asks the IObjectExporter interface on TCP/135 for the string bindings it would
hand out to a DCOM client. No authentication is required, so this reveals every
interface the target has -- including ones on networks you cannot reach.

Research by AirBus Security:
https://www.cyber.airbus.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/
"""

import argparse
import ipaddress
import socket
import sys

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, DCERPCException
from impacket.dcerpc.v5.dcomrt import IObjectExporter

DEFAULT_TIMEOUT = 2.0


class HostUnreachable(Exception):
    """The target did not return an OXID response."""


def expand_target(target):
    """Yield each host a -t value refers to.

    A value containing '/' is treated as a CIDR range and expanded; anything
    else is passed through untouched so hostnames still work.
    """
    if "/" not in target:
        yield target
        return

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as err:
        raise ValueError("%s is not a valid CIDR range (%s)" % (target, err))

    # .hosts() drops the network and broadcast addresses for ranges that have
    # them, and correctly yields the single address for a /32 or both for a /31.
    for host in network.hosts():
        yield str(host)


def expand_targets(targets):
    """Flatten and de-duplicate every -t value, preserving command-line order."""
    seen = set()
    for value in targets:
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            for host in expand_target(part):
                if host not in seen:
                    seen.add(host)
                    yield host


def get_adapter_info(host, timeout):
    """Return the addresses the target advertises, or raise HostUnreachable."""
    string_binding = r'ncacn_ip_tcp:%s' % host
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    # impacket defaults to 30s, which makes scanning a range unusable: every
    # firewalled address stalls the sweep for the full interval.
    rpctransport.set_connect_timeout(timeout)

    portmap = rpctransport.get_dce_rpc()
    portmap.set_auth_level(RPC_C_AUTHN_LEVEL_NONE)

    try:
        # ServerAlive2() connects and binds on its own, so no explicit
        # portmap.connect() here -- that would open a second, wasted socket.
        return [b['aNetworkAddr'] for b in IObjectExporter(portmap).ServerAlive2()]
    except DCERPCException as err:
        raise HostUnreachable(str(err))
    except socket.gaierror as err:
        # getaddrinfo() sits outside impacket's own error handling.
        raise HostUnreachable("could not resolve %s (%s)" % (host, err))
    except OSError as err:
        raise HostUnreachable(str(err))
    except Exception as err:
        # A host that answers on 135 but speaks something other than DCOM can
        # fail deep inside the response parser; one bad host must not end a scan.
        raise HostUnreachable("unexpected response (%s: %s)" % (type(err).__name__, err))
    finally:
        try:
            portmap.disconnect()
        except Exception:
            pass


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="IOXIDResolver.py",
        description="Enumerate a host's network interfaces through the DCOM "
                    "OXID resolver, without authentication.",
        epilog="examples:\n"
               "  IOXIDResolver.py -t 10.10.11.3\n"
               "  IOXIDResolver.py -t 10.10.11.0/24 -v\n"
               "  IOXIDResolver.py -t 10.10.11.3,10.10.12.0/24 -t dc01.corp.local\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-t", "--target", action="append", required=True, metavar="TARGET",
        help="IP address, hostname, or CIDR range. Accepts a comma-separated "
             "list and may be given more than once.")
    parser.add_argument(
        "-w", "--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SECONDS",
        help="connection timeout per host (default: %(default)s)")
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="also report hosts that did not answer")

    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    return args, parser


def main(argv):
    args, parser = parse_args(argv)

    try:
        targets = list(expand_targets(args.target))
    except ValueError as err:
        parser.error(str(err))

    if not targets:
        parser.error("no targets to scan")

    responded = 0
    for host in targets:
        try:
            addresses = get_adapter_info(host, args.timeout)
        except HostUnreachable as err:
            if args.verbose:
                print("[!] %s: %s" % (host, err))
            continue

        responded += 1
        print("[*] Retrieving network interface of " + host)
        for address in addresses:
            print("Address: " + address)

    if len(targets) > 1:
        print("[*] %d of %d hosts responded" % (responded, len(targets)))

    return 0 if responded else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(130)
