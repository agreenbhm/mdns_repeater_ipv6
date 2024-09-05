# MDNS Repeater IPv6

This is a FreeBSD service that will forward IPv6 mDNS requests between interfaces.  Meant to be run on pfSense/OPNsense.

### To use: 

1. Download the repo and simply extract the contents to /. It will put the script in /usr/local/bin and install the configuration files to setup a service and configure it.

2. Set the interfaces in /etc/rc.conf.d/mdns_repeater_ipv6.

3. Enable the service with 'service mdns_repeater_ipv6 enable'.

4. Start the service with 'service mdns_repeater_ipv6 start'.

