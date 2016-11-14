# proxy2

This version of [inaz/proxy2](https://github.com/inaz/proxy2) has been
modified specifically for MITM-proxying of the SSL connection between a PAN
GlobalProtect client running on Windows, and the VPN gateway.

# How to use

You'll need to have the openssl command-line utilities installed on a Linux box with a publicly-visible IP address.

On the Linux side:

1. `./setup_https_intercept.sh` (to generate the "fake" CA certificates)
2. `./proxy2.py [--cert client_certificate_w_pkey.pem] [-p 8080] gp_vpn_gateway.company.com
3. Watch the proxied traffic roll in.
  * This script looks in particular for `GET /ssl-tunnel-connect.sslvpn`, and handles it as a `CONNECT`-like request with bidirectional traffic, rather than the normal behavior of the HTTP `GET` verb.

On the Windows side:

1. Go to "Internet Options" and set your Linux host as your proxy
2. If you want to force GlobalProtect to use the HTTPS tunnel instead of ESP, then block outgoing UDP traffic to the GlobalProtect ESP-over-UDP port (usually 4501) using Windows Firewall"
3. Try to connect using the GlobalProtect VPN client.