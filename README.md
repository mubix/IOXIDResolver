# IOXIDResolver
IOXIDResolver.py from AirBus Security

I couldn't find an official repository for this code so I am posting it here. It's great research and super useful.

- The source from this blog post: [https://airbus-cyber-security.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/](https://www.cyber.airbus.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/)
- Part 2 of that blog post: [https://airbus-cyber-security.com/the-oxid-resolver-part-2-accessing-a-remote-object-inside-dcom/](https://www.cyber.airbus.com/the-oxid-resolver-part-2-accessing-a-remote-object-inside-dcom/)

## Usage

```
IOXIDResolver.py -t TARGET [-w SECONDS] [-v]

  -t, --target TARGET    IP address, hostname, or CIDR range. Accepts a
                         comma-separated list and may be given more than once.
  -w, --timeout SECONDS  connection timeout per host (default: 2.0)
  -v, --verbose          also report hosts that did not answer
```

## Example Run

```
user@host:~/IOXIDResolver$ python3 IOXIDResolver.py -t 10.10.11.3
[*] Retrieving network interface of 10.10.11.3
Address: HYPERV1
Address: 192.168.57.1
Address: 192.168.2.1
Address: 192.168.77.201
Address: 10.10.11.3
```

A CIDR range works too. Hosts that do not answer stay quiet unless you pass `-v`:

```
user@host:~/IOXIDResolver$ python3 IOXIDResolver.py -t 10.10.11.0/24
[*] Retrieving network interface of 10.10.11.3
Address: HYPERV1
Address: 192.168.57.1
Address: 10.10.11.3
[*] 1 of 254 hosts responded
```

Scanning is sequential, so a wide range takes roughly `hosts x timeout` in the
worst case. Exit status is 0 if any host responded, 1 if none did.
This is super useful because it helps you to identify hosts that have additional active interfaces, which usually means, virtual machines, VPNs, connected wireless, docker, etc. Basically "interesting".
