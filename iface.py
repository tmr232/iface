"""Interface Configuration

Usage:
  iface.py
  iface.py list
  iface.py dhcp <interface>
  iface.py set <interface> <ip> [--gw GW] [--metric METRIC]

Options:
  list               List all interfaces.
  dhcp               Set interface to DHCP.
  set                Set interface manually.
  <interface>        Interface index, current IP or name.
  <ip>               ip/mask to set.
  --gw GW            Gateway [default: none].
  --metric METRIC    Gateway metric [default: 0].
"""

# netsh interface ipv4 show addresses
# netsh interface ipv4 set address [name=]InterfaceName [source=]{dhcp | static [addr=]IPAddress [mask=]SubnetMask [gateway=]{none | DefaultGateway [[gwmetric=]GatewayMetric]}}

import re
import subprocess
import collections
import socket
import construct

import docopt

SHOW_ADDRS_REGEX = re.compile(
    r'Configuration for .*?"(?P<ifname>.*?)"\n'
    r'\s{4}.{38}(?P<dhcp>[^\n]*)\n'
    r'\s{4}.{38}(?P<ipaddr>[^\n]*)\n'
    r'\s{4}.{38}(?P<subnet>[^\n]*/(?P<maskwidth>\d*)[^\n]*)\n'
    r'(\s{4}.{38}(?P<gateway>[^\n]*)\n)?'
    r'(\s{4}.{38}(?P<gwmetric>[^\n]*)\n)?'
    r'\s{4}.{38}(?P<ifmetric>[^\n]*)\n',
    re.DOTALL | re.MULTILINE)

Interface = collections.namedtuple("Interface", "name dhcp ip mask gateway gwmetric")


def execute(command):
    args = command.split(" ")
    netsh = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = netsh.communicate()
    return output, err


def netsh_show_addresses():
    command = "netsh interface ipv4 show addresses"
    output, err = execute(command)
    return output


def iter_interfaces():
    output = netsh_show_addresses()
    output = output.replace("\r", "")
    for match in SHOW_ADDRS_REGEX.finditer(output):
        name = match.group("ifname")
        dhcp = ("Yes" == match.group("dhcp"))
        ip = match.group("ipaddr")
        mask = int(match.group("maskwidth"))

        gateway = match.group("gateway")
        gwmetric = match.group("gwmetric")

        yield Interface(name, dhcp, ip, mask, gateway, gwmetric)


def show_interfaces():
    for iface in iter_interfaces():
        print ("{}\n"
               "    {}/{}\n"
               "    {}").format(iface.name,
                                iface.ip,
                                iface.mask,
                                "DHCP" if iface.dhcp else "Manual",
                                iface.gateway,
                                iface.gwmetric)
        if None not in (iface.gateway, iface.gwmetric):
            print "    {} -> {}".format(iface.gateway,
                                        iface.gwmetric)
        print


def get_name_by_ip(ipaddr):
    for iface in iter_interfaces():
        if iface.ip == ipaddr:
            return iface.name

    raise IndexError("IP address did not match any interface ({})".format(ipaddr))


def set_iface_dhcp(ifname):
    command = 'netsh interface ipv4 set address name="{}" source=dhcp'.format(ifname)
    execute(command)


def set_iface_manual(ifname, ipaddr, mask, gateway, gwmetric):
    if gateway is None:
        gateway = "none"

    if gwmetric is None:
        gwmetric = ""

    command = ('netsh interface ipv4 set address'
               ' name="{ifname}"'
               ' source=static'
               ' addr={ipaddr}'
               ' mask={mask}'
               ' gateway={gateway}'
               ' {gwmetric}').format(ifname=ifname,
                                     ipaddr=ipaddr,
                                     mask=mask,
                                     gateway=gateway,
                                     gwmetric=gwmetric,
    )

    execute(command)


def bitmask32(width):
    return ~(-1 << width)


def netmask(width):
    return socket.inet_ntoa(construct.UBInt32(None).build((-1 << width) & 0xFFFFFFFF))


def parse_ip(masked_addr):
    if "/" in masked_addr:
        ip, mask = masked_addr.split("/")
        mask = int(mask)
    else:
        ip = masked_addr
        mask = 24

    return ip, netmask(mask)


def parse_interface(ifname):
    try:
        socket.inet_aton(ifname)
        name = get_name_by_ip(ifname)
    except:
        name = ifname

    if name not in [iface.name for iface in iter_interfaces()]:
        raise ValueError("Invalid interface ({})".format(ifname))

    return name


def main():
    arguments = docopt.docopt(__doc__)

    if arguments["list"]:
        show_interfaces()

    elif arguments["dhcp"]:
        iface = arguments["<interface>"]
        name = parse_interface(iface)
        set_iface_dhcp(name)

    elif arguments["set"]:
        name = parse_interface(arguments["<interface>"])
        ip, mask = parse_ip(arguments["<ip>"])

        gateway = arguments.get("--gw", None)
        if gateway is None:
            gwmetric = None
        else:
            gwmetric = arguments.get("--gwmetric", "0")

        set_iface_manual(name, ip, mask, gateway, gwmetric)

    else:
        show_interfaces()


if __name__ == "__main__":
    main()
