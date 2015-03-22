# dns-client

This repo contains a simple implementation of the DNS-client in C (socket progamming). The dns-client can perform the following features - 
  get ipv4 and ipv6 addresses for a domain name, canonical name, name server records, mail records, reverse lookup (given ip address, find the domain name), handle mulitple domain names and ip-addresses.
  The client has been implemented to handle responses larger than 512 bytes (TCP protocol is used for large responses).
