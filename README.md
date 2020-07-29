# IOXIDResolver
IOXIDResolver.py from AirBus Security

I couldn't find an official repository for this code so I am posting it here. It's great research and super useful.

- The source from this blog post: https://airbus-cyber-security.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/
- Part 2 of that blog post: https://airbus-cyber-security.com/the-oxid-resolver-part-2-accessing-a-remote-object-inside-dcom/

## Example Run

```
user@host:~/IOXIDResolver$ python IOXIDResolver.py -t 10.10.11.3
[*] Retrieving network interface of 10.10.11.3
Address: HYPERV1
Address: 192.168.57.1
Address: 192.168.2.1
Address: 192.168.77.201
Address: 10.10.11.3
```
