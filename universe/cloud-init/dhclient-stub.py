#!/usr/bin/python3

# SPDX-FileCopyrightText: 2023 BellSoft
# SPDX-License-Identifier: Apache-2.0

# Copyright 2023 BellSoft
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# ISC DHCP is EOL'ed, yet cloud-init wants to use dhclient to obtain
# the machine's DHCP lease *before* and *independent of* the normal
# system's DHCP process.  It calls dhclient in a "sandboxed" manner
# for that.  It's ok if dhclient is already your system's default DHCP
# client.  But dragging in dhclient just to send a single UDP packet
# is a bit of an overkill (given how it's EOL'ed, and wants GNU
# coreutils too).

import array
import atexit
import ipaddress
import logging
import os
import random
import selectors
import signal
import socket
import struct
import sys
import time

from typing import Dict, List, Tuple

logger = None

# options
g_pid_file_name: str = ''
g_lease_file_name: str = ''
g_debug: bool = False

# global state
g_interface: str = ''
g_macaddr: bytes = b''
g_reqxid: int = 0


# See cloud-init/cloudinit/net/dhcp.py - that's how it invokes
# dhclient, so that's exactly how we insist to be called
def usage(message: str = ''):
    if message:
        dst = sys.stderr
        ret = 2
        print(message, file = dst)
    else:
        dst = sys.stdout
        ret = 0

    ###
    print('usage: dhclient [-dv] -1 -pf pid-file -lf lease-file -sf /bin/true if0',
          file = dst, flush = True)
    if ret != 0:
        print('invoked as ', sys.argv, file = dst, flush = True)
    sys.exit(ret)


# cannot use getopt b/c dhclient uses "long" options with single dash
# ("-lf") and accepts options and non-option arguments intermixed (and
# cloud-init actually invokes it that way).
def parse_args() -> str:
    global g_debug, g_lease_file_name, g_pid_file_name
    have_1 = False
    scriptfile = None
    loglevel: int = logging.WARNING

    interface: str = ''

    args: List[str] = sys.argv[1:]
    while args:
        arg: str = args.pop(0)

        if arg == '-1':
            have_1 = True

        elif arg == '-d':
            loglevel = min(loglevel, logging.DEBUG)
            g_debug = True

        elif arg == '-v':
            loglevel = min(loglevel, logging.INFO)

        elif arg == '-lf':
            try:
                g_lease_file_name = args.pop(0)
            except IndexError:
                usage('-lf requires an argument')

        elif arg == '-pf':
            try:
                g_pid_file_name = args.pop(0)
            except IndexError:
                usage('-pf requires an argument')

        elif arg == '-sf':
            try:
                scriptfile = args.pop(0)
            except IndexError:
                usage('-sf requires an argument')
            if scriptfile != '/bin/true':
                usage('-sf only accepts /bin/true')

        elif arg[0] == '-':
            usage(f'unsupported option {arg}')

        elif arg == '':
            usage('empty interface name')

        elif interface:
            usage(f'only one interface can be specified ({interface})')

        else:
            interface = arg

    if not interface:
        usage('interface not specified')

    if not have_1:
        usage('expected -1 flag missing')

    if not g_pid_file_name:
        usage('expected -pf flag missing')

    if not g_lease_file_name:
        usage('expected -lf flag missing')

    if not scriptfile:
        usage('expected -sf flag missing')

    init_logger(loglevel)
    return interface


def init_logger(loglevel: int):
    global logger

    plainMessage = logging.Formatter('%(message)s')
    fancyMessage = logging.Formatter('%(asctime)s: %(levelname)s: %(message)s')

    logger = logging.getLogger('dhclient')
    logger.setLevel(logging.DEBUG)

    logfile = logging.FileHandler('/var/log/dhclient-stub.log')
    logfile.setFormatter(fancyMessage)
    logfile.setLevel(logging.DEBUG)
    logger.addHandler(logfile)

    errlog = logging.StreamHandler(sys.stderr)
    errlog.setFormatter(plainMessage)
    errlog.setLevel(logging.WARNING)
    logger.addHandler(errlog)

    outlog = logging.StreamHandler(sys.stdout)
    outlog.setFormatter(plainMessage)
    outlog.addFilter(lambda record:
                     1 if record.levelno >= loglevel \
                          and record.levelno < logging.WARNING \
                     else 0)
    logger.addHandler(outlog)


def main():
    interface = parse_args()
    macaddr = getmac(interface)
    discover, xid = mkdiscover(macaddr)

    # set up global state
    global g_interface, g_macaddr, g_reqxid
    g_interface = interface
    g_macaddr = macaddr
    g_reqxid = xid

    sudp = get_udp_socket(interface) # send (I'm lazy)
    sraw = get_raw_socket(interface) # receive

    sel = selectors.DefaultSelector()
    sel.register(sraw, selectors.EVENT_READ, have_raw_udp)

    # might be useful when debugging raw packet parser
    # sel.register(sudp, selectors.EVENT_READ, have_dhcp_reply)

    nsent = sudp.sendto(discover, ('255.255.255.255', PORT_BOOTPS))
    assert nsent == len(discover)

    # wait for reply
    timeout = 3
    done = False

    now = time.time()
    end = now + timeout
    while end > now:
        timeout = end - now
        events = sel.select(timeout = timeout)

        for key, mask in events:
            callback = key.data
            done = callback(key.fileobj)
            if done:
                logger.info('DONE: obtained a lease')
                break

        if done:
            break

        now = time.time()

    sel.close()
    sraw.close()
    sudp.close()

    if not done:
        logger.warn('failed to obtain a lease')
        return 2

    if not g_debug:
        return daemonize_and_pause()

    return 0


def daemonize_and_pause():
    logger.info('... waiting for cloud-init to kill me')
    child = os.fork()
    if child != 0:              # parent
        sys.exit(0)

    os.setsid()
    os.chdir('/')
    # close descriptors...
    mkpidfile()
    os.closerange(0, 256)       # "when in doubt use brute force"
    signal.pause()
    return 0


def mkpidfile():
    global g_pid_file_name
    with open(g_pid_file_name, 'w') as pidfile:
        print(os.getpid(), file = pidfile)
    atexit.register(rmpid)


def rmpid():
    global g_pid_file_name
    try:
        os.unlink(g_pid_file_name)
    except Exception as e:
        logger.exception(e)



######################################################################
#
# BOOTP/DHCP defines
#
#   https://tools.ietf.org/html/rfc951	BOOTP
#   https://tools.ietf.org/html/rfc2132	DHCP options
#

ETH_P_IP = 0x0800               # for the raw socket "protocol"

PORT_BOOTPS = 67
PORT_BOOTPC = 68

BOOTP_OP_REQUEST = 1
BOOTP_OP_REPLY = 1

BOOTP_HTYPE_ARP_ETHERNET = 1
BOOTP_HLEN_ARP_ETHERNET = 6

BOOTP_DHCP_FLAG_BROADCAST = 0x8000

# Format for struct.pack
BOOTPHDR = ('>'                 # big endian
            #
            + 'B'               # op
            + 'B'               # htype
            + 'B'               # hlen
            + 'B'               # hops
            #
            + 'I'               # xid
            #
            + 'H'               # secs
            + 'H'               # DHCP flags (unused in BOOTP)
            #
            + 'I'               # ciaddr
            + 'I'               # yiaddr
            + 'I'               # siaddr
            + 'I'               # giaddr
            #
            + '16s'             # chaddr
            + '64s'             # sname
            + '128s'            # file
            )

# Contents of DHCP vendor area
DHCP_COOKIE = b'\x63\x82\x53\x63'

OPT_PAD = 0
OPT_END = 255

OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DOMAIN_NAME_SERVER = 6
OPT_HOST_NAME = 12
OPT_DOMAIN_NAME = 15
OPT_BROADCAST_ADDRESS = 28
OPT_STATIC_ROUTES =  33
OPT_OPTION_OVERLOAD =  52
OPT_MESSAGE_TYPE = 53
OPT_PARAMETER_REQUEST_LIST = 55
OPT_CLASSLESS_STATIC_ROUTES = 121

# OPT_MESSAGE_TYPE
DHCP_DISCOVER = 1
DHCP_OFFER    = 2

OPT_OPTION_OVERLOAD_FILE = 1
OPT_OPTION_OVERLOAD_SNAME = 2
OPT_OPTION_OVERLOAD_BOTH = 3


def getmac(interface: str) -> bytes:
    with open(f'/sys/class/net/{interface}/address', 'r') as address:
        addr_line = address.readline()
    addr_hex = addr_line.rstrip().replace(':', '')
    addr_bytes = bytes.fromhex(addr_hex)
    assert len(addr_bytes) == BOOTP_HLEN_ARP_ETHERNET
    return addr_bytes


def get_udp_socket(interface: str):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setblocking(False)
    s.bind(('0.0.0.0', PORT_BOOTPC))
    return s


def get_raw_socket(interface: str):
    s = socket.socket(socket.PF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
    s.setblocking(False)
    return s


# Compute IP checksum.  We only need to compute a handful so don't
# bother with efficiency too much.
def cksum(data: bytes, add: int = 0) -> int:
    # pad to 2 bytes (for 'H' below)
    if len(data) % 2 != 0:
        data += b'\x00'

    if add != 0:
        csum = ~add & 0xffff
    else:
        csum = 0

    # we can add 1-complement in any endianness
    csum = csum + sum(array.array('H', data))

    # reduce by bringing carry back into the lower 16-bits
    #      LO                HI (carry)
    csum = (csum & 0xffff) + (csum >> 16) # can overfow
    csum = (csum & 0xffff) + (csum >> 16) #  so one more time

    return ~csum & 0xffff


def mkdiscover(macaddr: bytes) -> Tuple[bytes, int]:
    xid = random.randint(0, 0xffffffff)

    bootp = struct.pack(BOOTPHDR,
        BOOTP_OP_REQUEST,         # op
        BOOTP_HTYPE_ARP_ETHERNET, # htype
        BOOTP_HLEN_ARP_ETHERNET,  # hlen
        0,                        # hops
        #
        xid,                      # xid
        #
        1,                        # secs
        BOOTP_DHCP_FLAG_BROADCAST,# flags
        #
        0,                        # ciaddr
        0,                        # yiaddr
        0,                        # siaddr
        0,                        # giaddr
        #
        macaddr,                  # chaddr
        b'',                      # sname
        b''                       # file
        )

    vendor  = DHCP_COOKIE
    vendor += struct.pack('BB' + 'B', OPT_MESSAGE_TYPE, 1, DHCP_DISCOVER)

    opts  = b''
    opts += struct.pack('B', OPT_SUBNET_MASK)
    opts += struct.pack('B', OPT_BROADCAST_ADDRESS)
    opts += struct.pack('B', OPT_ROUTER)
    opts += struct.pack('B', OPT_STATIC_ROUTES)
    # opts += struct.pack('B', OPT_CLASSLESS_STATIC_ROUTES)

    vendor += struct.pack('BB', OPT_PARAMETER_REQUEST_LIST, len(opts))
    vendor += opts

    vendor += struct.pack('B', OPT_END)

    bootp += struct.pack('64s', vendor)
    return bootp, xid


def have_raw_udp(raw):
    packet, server = raw.recvfrom(1024)
    logger.debug(f'> raw packet from {server}')
    if g_debug:
        for offset in range(0, 64, 16):
            logger.debug('  ' + packet[offset: offset+16].hex(' '))

    try:
        return parse_raw_udp(packet)
    except Exception as ex:
        logger.exception(ex)
    return False


def parse_raw_udp(packet):
    ipversion = packet[0] & 0xf0
    hlen = (packet[0] & 0x0f) * 4

    csum = cksum(packet[:hlen])
    if csum != 0:
        logger.debug('... bad ip header checksum')
        return False

    if ipversion != 0x40:
        logger.debug('... bad ip version')
        return False

    protocol = packet[9]
    if protocol != socket.IPPROTO_UDP:
        logger.debug(f'... ignore protocol {protocol}')
        return False

    # we are running without any address configured on the interface
    # and we have requested a broadcast, so look for broadcast packets
    (daddr,) = struct.unpack_from('>I', packet[16:])
    if daddr != 0xffffffff:
        logger.debug(f'... ignore packet to {ipaddress.IPv4Address(daddr)}')
        return False

    udp = packet[hlen:]

    (udpsum,) = struct.unpack_from('>H', udp[6:])
    if udpsum != 0:
        pseudo = packet[12:12+8]    # src ip, dst ip
        pseudo += b'\x00\x11' + udp[4:4+2]
        csum = cksum(pseudo)

        csum = cksum(udp, add = csum)
        if csum != 0:
            logger.debug(f'... bad udp checksum {csum}')
            return False

    sport, dport = struct.unpack_from('>HH', udp)
    if sport != PORT_BOOTPS or dport != PORT_BOOTPC:
        logger.debug(f'... ignore packet from port {sport} to port {dport}')
        return False

    udp_payload = udp[8:]
    return parse_dhcp_reply(udp_payload)


def have_dhcp_reply(s):
    reply, server = s.recvfrom(1024)
    logger.debug(f'> udp reply from {server}')

    try:
        return parse_dhcp_reply(reply)
    except Exception as ex:
        logger.exception(ex)
    return False


def parse_dhcp_reply(reply):
    global g_macaddr, g_reqxid
    global g_lease_file_name, g_interface

    (op, htype, hlen, hops,
     xid,
     secs, flags,
     ciaddr, yiaddr, siaddr, giaddr,
     chaddr,
     sname, file
     ) = struct.unpack_from(BOOTPHDR, reply, 0)

    # make sure this is a reply to the request we have sent
    # i.e. its chaddr and xid match that of our request
    if htype != BOOTP_HTYPE_ARP_ETHERNET:
        logger.debug(f'... unexpected htype {htype}')
        return False

    if hlen != BOOTP_HLEN_ARP_ETHERNET:
        logger.debug(f'... unexpected hlen {hlen}')
        return False

    mac = chaddr[:hlen]
    if mac != g_macaddr:
        logger.debug(f'... unexpected chaddr {mac.hex(":")}')
        return False

    if xid != g_reqxid:
        logger.debug(f'... unexpected xid {g_reqxid}')
        return False

    # make sure it's a DHCP reply (not that it's likely that a modern
    # cloud runs plain BOOTP)
    vendor = reply[struct.calcsize(BOOTPHDR):]
    if not vendor.startswith(DHCP_COOKIE):
        logger.warn('BOOTP reply is not DHCP')
        return False

    options: Dict[int, bytes] = {}
    collect_options(options, vendor[len(DHCP_COOKIE) :])

    if OPT_OPTION_OVERLOAD in options:
        overloads = struct.unpack('B', options[OPT_OPTION_OVERLOAD])
        if overloads == OPT_OPTION_OVERLOAD_FILE:
            collect_options(options, file)
        elif overloads == OPT_OPTION_OVERLOAD_SNAME:
            collect_options(options, sname)
        elif overloads == OPT_OPTION_OVERLOAD_BOTH:
            collect_options(options, file)
            collect_options(options, sname)
        else:
            logger.warn(f'bad option overload value {overloads}')

    if OPT_MESSAGE_TYPE not in options:
        logger.warn('no DHCP message type option')
        return False

    (mtype,) = struct.unpack('B', options[OPT_MESSAGE_TYPE])
    if mtype != DHCP_OFFER:
        logger.warn(f'unexpected DHCP message type {mtype}')
        return False

    addr = ipaddress.IPv4Address(yiaddr)
    logger.info(f'my addr is {addr}')

    mask = None
    if OPT_SUBNET_MASK in options:
        try:
            (imask,) = struct.unpack('>I', options[OPT_SUBNET_MASK])
            mask = ipaddress.IPv4Address(imask)
            logger.info(f'... subnet mask = {mask}')
        except Exception as ex:
            logger.exception(f'... bad subnet mask: {ex}')

    bcast = None
    if OPT_BROADCAST_ADDRESS in options:
        try:
            (ibcast,) = struct.unpack('>I', options[OPT_BROADCAST_ADDRESS])
            bcast = ipaddress.IPv4Address(ibcast)
            logger.info(f'... broadcast = {bcast}')
        except Exception as ex:
            logger.exception(f'... bad subnet mask: {ex}')

    routers = []
    if OPT_ROUTER in options:
        try:
            for (irouter,) in struct.iter_unpack('>I', options[OPT_ROUTER]):
                router = ipaddress.IPv4Address(irouter)
                routers.append(router)
                logger.info(f'... router {router}')
        except Exception as ex:
            logger.exception(f'... bad router: {ex}')

    static_routes = []
    if OPT_STATIC_ROUTES in options:
        try:
            for (idst, igw) in struct.iter_unpack('>II', options[OPT_STATIC_ROUTES]):
                dst = ipaddress.IPv4Address(idst)
                gw  = ipaddress.IPv4Address(igw)
                static_routes.append((dst, gw))
                logger.info(f'... route {dst} via {gw}')
        except Exception as ex:
            logger.exception(f'... bad static routes: {ex}')

    with open(g_lease_file_name, 'w') as lf:
            print('lease {', file = lf)
            print(f'  interface "{g_interface}";', file = lf)
            if addr:
                print(f'  fixed-address {addr};', file = lf)
            if mask:
                print(f'  option subnet-mask {mask};', file = lf)
            if bcast:
                print(f'  option broadcast-address {bcast};', file = lf)
            if routers:
                print('  option routers', end = '', file = lf)
                sep = ''
                for r in routers:
                    print(sep, r, end = '', file = lf)
                    sep = ","
                print(';', file = lf)
            print('}', file = lf)

    return True


def collect_options(options: Dict[int, bytes], data: bytes):
    offset = 0
    while offset < len(data):
        opt = data[offset]
        offset += 1

        # single byte surface syntax options
        if opt == OPT_PAD:
            pass
        if opt == OPT_END:
            break

        # length byte of real, semantic options
        optlen = data[offset]
        offset += 1

        value = data[offset : offset+optlen]
        if opt in options:
            value = options[opt] + value # rfc3396

        options[opt] = value
        offset += optlen


## --
if __name__ == '__main__':
    sys.exit(main())
