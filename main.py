import json
import re
import ipaddress
from concurrent import futures
from collections import defaultdict
from pyats.topology import loader

SITE_FILE = 'test.yaml'
EXCLUDE_FILE = 'exclude_ips.txt'
COMMENTS_FILE = 'comments.txt'
WORKERS = 5
PING_WORKERS = 10
RUN_PINGS = True
# Exclude these MAC addresses from the ARP report - e.g. MACs of network devices
# Using the same MAC on multiple sub-interfaces.
EXCLUDE_MACS = [
    '0009.0f09.0019',
    '503d.e578.8c3e',
    '503d.e578.8b36',
    'INCOMPLETE',
]
# Exclude these networks from the ARP report - e.g. OOB networks.
EXCLUDE_NETS = [
    '192.168.0.0/24',
]
# Exclude these networks from the ping sweeps
EXCLUDE_PING_NETS = [
    '192.168.0.0/24',
]


def get_port_mac(mac):
    ports_str = ''
    if mac in macs_ints:
        mac_list = macs_ints[mac]
        ports_str = '-;-'.join([x for x in [' '.join(y) for y in mac_list]])
    return ports_str


def get_comments(ip):
    if ip in ip_comments:
        return ip_comments[ip]
    else:
        return ''


def include_ip(ip):
    if not any([ip in ipaddress.ip_network(x)
                for x in EXCLUDE_NETS]):
        return True


def include_mac(mac):
    if not mac.upper() in [x.upper() for x in EXCLUDE_MACS]:
        return True


def ios_ping_sweep(testbed, dev):
    pinged = []
    ping_cmd = 'ping {} repeat 1 timeout 0'
    asa = testbed.devices[dev]
    direct_nets = asa.parse('show ip route connected')
    for net, dets in direct_nets['vrf']['default'] \
            ['address_family']['ipv4']['routes'].items():
        if dets['source_protocol'] == 'connected':
            if any([ipaddress.ip_interface(net) in x for x in exc_ping_nets]):
                continue
            host_ips = ipaddress.ip_network(net).hosts()
            for host_ip in host_ips:
                asa.execute(ping_cmd.format(host_ip))
                pinged.append(host_ip)
    return pinged[0], pinged[-1]


def asa_ping_sweep(testbed, dev):
    pinged = []
    ping_cmd = 'ping {} repeat 1 timeout 0'
    asa = testbed.devices[dev]
    direct_nets = asa.parse('show route')
    for net, dets in direct_nets['vrf']['default'] \
            ['address_family']['ipv4']['routes'].items():
        if dets['source_protocol'] == 'connected':
            if any([ipaddress.ip_interface(net) in x for x in exc_ping_nets]):
                continue
            host_ips = ipaddress.ip_network(net).hosts()
            for host_ip in host_ips:
                asa.execute(ping_cmd.format(host_ip))
                pinged.append(host_ip)
    return pinged[0], pinged[-1]


def nxos_ping_sweep(testbed, dev):
    pinged = []
    ping_cmd = 'ping {} vrf {} count 1 timeout 0'
    exc_vrfs = ('management', 'vpc_keepalive',)
    nxos = testbed.devices[dev]
    vdcs = nxos.list_vdc()
    for vdc in vdcs:
        # Skip Global VDC
        if vdc == dev:
            continue
        nxos.switchto(vdc)

        # Get the VRRs
        vrfs = nxos.parse('show vrf')

        # Loop through each vrf
        for vrf in vrfs['vrfs']:
            if vrf in exc_vrfs:
                continue
            direct_nets = nxos.parse('show ip route direct vrf ' + vrf)

            # Loop through each network
            for net in direct_nets['vrf'] \
                    [vrf]['address_family']['ipv4']['routes']:
                # Exclude networks from the pings
                if any([ipaddress.ip_interface(net) in x for x in exc_ping_nets]):
                    continue
                # Get all host ips and ping
                host_ips = ipaddress.ip_network(net).hosts()
                for host_ip in host_ips:
                    nxos.execute(ping_cmd.format(host_ip, vrf))
                    pinged.append(host_ip)
    return pinged[0], pinged[-1]


def nxos_arps(testbed, dev):
    nxos = testbed.devices[dev]
    vdcs = nxos.list_vdc()
    for vdc in vdcs:
        # Skip Global VDC
        if vdc == dev:
            continue
        nxos.switchto(vdc)
        dev_vdc = dev + '-' + vdc
        # Get every arp and yield the device, IP, MAC and interface
        nxos_arps = nxos.parse('show ip arp vrf all')
        for intf, dets in nxos_arps['interfaces'].items():
            for neighbor, ne_dets in dets['ipv4']['neighbors'].items():
                yield dev_vdc, ne_dets['ip'], ne_dets['link_layer_address'], intf


def asa_arps(testbed, dev):
    asa = testbed.devices[dev]
    asa_arps = asa.parse("show arp")
    for intf, dets in asa_arps.items():
        for neighbor, ne_dets in dets['ipv4']['neighbors'].items():
            yield dev, ne_dets['ip'], ne_dets['link_layer_address'], intf


def ios_arps(testbed, dev):
    ios = testbed.devices[dev]
    ios_arps = ios.parse("show arp")
    for intf, dets in ios_arps['interfaces'].items():
        for neighbor, ne_dets in dets['ipv4']['neighbors'].items():
            yield dev, ne_dets['ip'], ne_dets['link_layer_address'], intf


def f5_ips(testbed, dev):
    f5 = testbed.devices[dev]
    f5.connect(alias='rest', via='rest')
    f5.rest.connected

    # Get self IPs, VIPs and SNATs
    urls = (
        '/mgmt/tm/net/self',
        '/mgmt/tm/ltm/virtual-address',
        '/mgmt/tm/ltm/snat-translation',
    )

    for url in urls:
        rest_output = f5.rest.get(url)
        x = json.loads(rest_output.content.decode('utf-8'))
        if 'items' in x:
            for i in x['items']:
                # Filter out IPv6
                if '::' in i['address']:
                    continue
                if 'any' not in i['address']:
                    if 'vlan' in i:
                        # sub out the Route Domain ID if there is one.
                        yield dev, re.sub(r'%\d+', '', i['address']), i['vlan']
                    else:
                        yield dev, re.sub(r'%\d+', '', i['address']), None


def ios_ips(testbed, dev):
    router = testbed.devices[dev]
    router_ints = router.parse('show interfaces')
    for intf, dets in router_ints.items():
        if 'ipv4' in dets:
            for ip in dets['ipv4']:
                yield dev, ip, intf


def get_hsrp(hsrp_dict):
    # Recurse to get the IP due to the nesting depth.
    if 'primary_ipv4_address' in hsrp_dict:
        return hsrp_dict['primary_ipv4_address']['address']
    for _, vals in hsrp_dict.items():
        if isinstance(vals, dict):
            return get_hsrp(vals)


def nxos_ips(testbed, dev):
    nxos = testbed.devices[dev]
    vdcs = nxos.list_vdc()
    for vdc in vdcs:
        # Skip Global VDC
        if vdc == dev:
            continue
        nxos.switchto(vdc)
        dev_vdc = dev + '-' + vdc

        # Return Interface IPs
        nxos_ints = nxos.parse('show interface')
        for intf, dets in nxos_ints.items():
            if 'ipv4' in dets:
                for ip in dets['ipv4']:
                    yield dev_vdc, ip, intf

        # Return HSRP addresses
        hsrps = nxos.parse('show hsrp all')
        for intf, hsrp in hsrps.items():
            hsrp_ip = get_hsrp(hsrp)
            if hsrp_ip is not None:
                yield dev_vdc, get_hsrp(hsrp), intf


def asa_ips(testbed, dev):
    # Some ASAs don't have the interface summary command
    custom_cmd = {
        'ASA-OLD-VERSION': "show interface detail"
    }
    asa = testbed.devices[dev]
    if dev in custom_cmd:
        asa_int = asa.parse(custom_cmd[dev])
    else:
        asa_int = asa.parse("show interface summary")
    for intf, dets in asa_int['interfaces'].items():
        if 'ipv4' in dets:
            for ip in dets['ipv4']:
                yield dev, ip + '/' + dets['subnet'], intf


def nxos_macs(testbed, dev):
    nxos = testbed.devices[dev]
    vdcs = nxos.list_vdc()
    for vdc in vdcs:
        # Skip Global VDC
        if vdc == dev:
            continue
        nxos.switchto(vdc)
        dev_vdc = dev + '-' + vdc
        try:
            mac_addr_table = nxos.parse('show mac address-table')
        except:
            continue
        for vlan, dets in mac_addr_table['mac_table']['vlans'].items():
            for mac_addr in dets['mac_addresses']:
                mac_ints = dets['mac_addresses'][mac_addr]['interfaces']
                for mac_int in mac_ints:
                    # Only match these patterns for interfaces e.g ignore VPC Peer link
                    if any([re.match(x, mac_int) for x in (r'Po.*', r'.*Eth.*\d+/\d+')]):
                        yield mac_addr, dev_vdc, mac_int, vlan


def ios_macs(testbed, dev):
    ios = testbed.devices[dev]
    mac_addr_table = ios.parse('show mac address-table')
    for vlan, dets in mac_addr_table['mac_table']['vlans'].items():
        for mac_addr in dets['mac_addresses']:
            mac_ints = dets['mac_addresses'][mac_addr]['interfaces']
            for mac_int in mac_ints:
                if any([re.match(x, mac_int) for x in (r'Po.*', r'.*Eth.*\d+/\d+')]):
                    yield mac_addr, dev, mac_int, vlan


# --------------------------------------------------------------
# Threadpool functions
#
# get_<>_devs()
# These generators are consumed by threadpool executor
# To get the devices to gather IPs from run ping sweeps etc.
#
# master_<>()
# These functions are called from the threadpool executor
# And calls the correct function
# Based on the OS type from the function maps below.
#
# --------------------------------------------------------------


def get_ips_devs():
    for dev in testbed.devices:
        os = testbed.devices[dev].os
        if os in get_ips_fmap:
            yield (testbed, dev)


def master_int(args):
    testbed, dev = args
    os = testbed.devices[dev].os
    return list(get_ips_fmap[os](testbed, dev))


def get_devs_pings():
    for dev in testbed.devices:
        os = testbed.devices[dev].os
        if os in ping_sweep_fmap:
            yield (testbed, dev)


def master_pinger(args):
    testbed, dev = args
    os = testbed.devices[dev].os
    ping_sweep_fmap[os](testbed, dev)


def get_devs_arps():
    for dev in testbed.devices:
        os = testbed.devices[dev].os
        if os in get_arps_fmap:
            yield (testbed, dev)


def master_arps(args):
    testbed, dev = args
    os = testbed.devices[dev].os
    return list(get_arps_fmap[os](testbed, dev))


def get_devs_macs():
    for dev in testbed.devices:
        os = testbed.devices[dev].os
        if os in get_macs_ints_fmap:
            hw_type = testbed.devices[dev].type
            if hw_type != 'router':
                yield (testbed, dev)


def master_macs(args):
    testbed, dev = args
    os = testbed.devices[dev].os
    return list(get_macs_ints_fmap[os](testbed, dev))


# Networks to exclude from ping sweeps
exc_ping_nets = [ipaddress.ip_network(x) for x in EXCLUDE_PING_NETS]

# List of IPs to exclude from the ARP report.
# Network devices not automatically detected e.g standby IP on ASAs.
with open(EXCLUDE_FILE, encoding='utf-8') as F:
    exclude_ips = set([ipaddress.ip_address(x.strip())
                       for x in F.readlines()])

# Networks to exclude from the ARP report
exclude_nets = [ipaddress.ip_network(x) for x in EXCLUDE_NETS]

# List of IPs with comments to be included each time the report is run
# Add your comments to this file instead of the outputted report to include it each time
with open(COMMENTS_FILE, encoding='utf-8') as F:
    ip_comments = [x.strip().split() for x in F.readlines()]
    ip_comments = {ipaddress.ip_address(x[0]): ' '.join(x[1:]) for x in ip_comments}

# Function maps by OS type
get_arps_fmap = {
    'nxos': nxos_arps,
    'asa': asa_arps,
    'ios': ios_arps,
}

get_ips_fmap = {
    'bigip': f5_ips,
    'nxos': nxos_ips,
    'ios': ios_ips,
    'asa': asa_ips,
}

get_macs_ints_fmap = {
    'nxos': nxos_macs,
    'ios': ios_macs,
}

ping_sweep_fmap = {
    'nxos': nxos_ping_sweep,
    'asa': asa_ping_sweep,
    'ios': ios_ping_sweep,
}

testbed = loader.load(SITE_FILE)
testbed.connect()

# Get all the IP addresses on each network device.
# These will be excluded from the ARP report since we only want servers.
all_ints = {}
if WORKERS > 1:
    with futures.ThreadPoolExecutor(WORKERS) as executor:
        res = executor.map(master_int, get_ips_devs())
    # Loop through results from each device from threadpool
    for dev_out in res:
        for dev_name, ip, intf in dev_out:
            all_ints[ipaddress.IPv4Interface(ip)] = (dev_name, intf)
# If WORKERS is set to 1 then don't thread.
else:
    for args in get_ips_devs():
        for dev_name, ip, intf in master_int(args):
            all_ints[ipaddress.IPv4Interface(ip)] = (dev_name, intf)

# Execute pings on all L3 gateway devices
if RUN_PINGS:
    with futures.ThreadPoolExecutor(PING_WORKERS) as executor:
        res = executor.map(master_pinger, get_devs_pings())
    # Reconnect after running pings due to length of time
    testbed.connect()

with futures.ThreadPoolExecutor(WORKERS) as executor:
    res = executor.map(master_arps, get_devs_arps())

# Get all the ARPS on the 7ks and ASAs.
all_arps = {}
for dev_out in res:
    for dev_name, ip, mac_addr, intf in dev_out:
        all_arps[ipaddress.ip_address(ip)] = (dev_name, mac_addr, intf)

# Get MAC addresses and ports from NXOS and IOS with type of "switch"
with futures.ThreadPoolExecutor(WORKERS) as executor:
    res = executor.map(master_macs, get_devs_macs())

macs_ints = defaultdict(list)
for dev_out in res:
    for mac, dev_name, intf, vlan in dev_out:
        macs_ints[mac].append((dev_name, intf, vlan))

# Create a set of all IPs owned by network devices
# And a set of all IPs from ARP tables
net_ips = set([x.ip for x, _ in all_ints.items()])
arp_ips = set([x for x, _ in all_arps.items()])

# Print out all IPs, MACs and Interfaces.
# Excluding those owned by network devices.
# And excluding those in the exclude_ips file.
with open('ARP-Report.csv', 'w', encoding='utf-8') as F:
    for ip in sorted(arp_ips.difference(net_ips.union(exclude_ips))):
        mac = all_arps[ip][1]
        if include_ip(ip) and include_mac(mac):
            F.write(','.join([str(ip)] + list(all_arps[ip]) + [get_comments(ip)] + [get_port_mac(mac)]) + '\n')
