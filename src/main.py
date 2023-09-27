#!/usr/bin/env python3
import argparse
import threading
import socket
import struct
import codecs
import time
import sys
import os
import fcntl
import struct
import ipaddress
import netifaces
import fnmatch


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(
        fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode()))[20:24])


def get_network_interfaces(netcard_wild):
    interfaces = netifaces.interfaces()
    return [
        iface for iface in interfaces if fnmatch.fnmatch(iface, netcard_wild)
    ]


# Fix OpenWRT Python codecs issues:
#   Always fallback to ASCII when specified codec is not available.
try:
    codecs.lookup('idna')
    codecs.lookup('utf-8')
except LookupError:

    def search_codec(_):
        return codecs.CodecInfo(codecs.ascii_encode,
                                codecs.ascii_decode,
                                name='ascii')

    codecs.register(search_codec)


class Logger(object):
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4

    def __init__(self, level=INFO):
        self.level = level

    def debug(self, msg):
        if self.level <= Logger.DEBUG:
            sys.stderr.write("[DEBUG] - " + str(msg) + "\n")
            sys.stderr.flush()

    def info(self, msg):
        if self.level <= Logger.INFO:
            sys.stderr.write("[INFO] - " + str(msg) + "\n")
            sys.stderr.flush()

    def warning(self, msg):
        if self.level <= Logger.WARNING:
            sys.stderr.write("[WARNING] - " + str(msg) + "\n")
            sys.stderr.flush()

    def error(self, msg):
        if self.level <= Logger.ERROR:
            sys.stderr.write("[ERROR] - " + str(msg) + "\n")
            sys.stderr.flush()


class StunClient(object):
    # Note: IPv4 Only.
    # Reference:
    #     https://www.rfc-editor.org/rfc/rfc3489
    #     https://www.rfc-editor.org/rfc/rfc5389
    #     https://www.rfc-editor.org/rfc/rfc8489

    # Servers in this list must be compatible with rfc5389 or rfc8489
    stun_server_tcp = [
        "fwa.lifesizecloud.com", "stun.isp.net.au", "stun.freeswitch.org",
        "stun.voip.blackberry.com", "stun.nextcloud.com",
        "stun.stunprotocol.org", "stun.sipnet.com", "stun.radiojar.com",
        "stun.sonetel.com", "stun.voipgate.com"
    ]
    # Servers in this list must be compatible with rfc3489, with "change IP" and "change port" functions available
    stun_server_udp = ["stun.miwifi.com", "stun.qq.com"]
    MTU = 1500
    STUN_PORT = 3478
    MAGIC_COOKIE = 0x2112a442
    BIND_REQUEST = 0x0001
    BIND_RESPONSE = 0x0101
    FAMILY_IPV4 = 0x01
    FAMILY_IPV6 = 0x02
    CHANGE_PORT = 0x0002
    CHANGE_IP = 0x0004
    ATTRIB_MAPPED_ADDRESS = 0x0001
    ATTRIB_CHANGE_REQUEST = 0x0003
    ATTRIB_XOR_MAPPED_ADDRESS = 0x0020
    NAT_OPEN_INTERNET = 0
    NAT_FULL_CONE = 1
    NAT_RESTRICTED = 2
    NAT_PORT_RESTRICTED = 3
    NAT_SYMMETRIC = 4
    NAT_SYM_UDP_FIREWALL = 5
    NAT_TYPE_MAP = {
        NAT_OPEN_INTERNET: "Open Internet",
        NAT_SYM_UDP_FIREWALL: "Symmetric UDP firewall",
        NAT_FULL_CONE: "Full cone (NAT 1)",
        NAT_RESTRICTED: "Restricted (NAT 2)",
        NAT_PORT_RESTRICTED: "Port restricted (NAT 3)",
        NAT_SYMMETRIC: "Symmetric (NAT 4)",
    }

    def __init__(self, log_level=Logger.INFO):
        self.logger = Logger(log_level)
        self.stun_ip_tcp = []
        self.stun_ip_udp = []
        # if not self.check_reuse_ability():
        #     raise OSError("This OS or Python does not support reusing ports!")
        self.logger.info("Getting STUN server IP...")
        # for hostname in self.stun_server_tcp:
        #     self.stun_ip_tcp.extend(self.resolve_hostname(hostname))
        for hostname in self.stun_server_udp:
            self.stun_ip_udp.extend(self.resolve_hostname(hostname))
        if not self.stun_ip_udp:
            raise Exception(
                "No public STUN server is avaliable. Please check your Internet connection."
            )

    def get_free_port(self, udp=False):
        if udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if 'SO_REUSEPORT' in dir(socket):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(('', 0))
        ret = sock.getsockname()[1]
        sock.close()
        return ret

    def check_reuse_ability(self):
        try:
            test_port = self.get_free_port()
            s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if 'SO_REUSEPORT' in dir(socket):
                s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s1.bind(("0.0.0.0", test_port))
            s1.listen(1)
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if 'SO_REUSEPORT' in dir(socket):
                s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s2.bind(("0.0.0.0", test_port))
            s2.listen(1)
            s1.close()
            s2.close()
            return True
        except OSError as e:
            self.logger.debug("%s: %s" % (e.__class__.__name__, e))
            return False

    def resolve_hostname(self, hostname):
        self.logger.debug("Resolving hostname [%s]..." % hostname)
        try:
            host, alias, ip_addresses = socket.gethostbyname_ex(hostname)
            return ip_addresses
        except Exception as e:
            self.logger.debug("%s: %s" % (e.__class__.__name__, e))
            return []

    def random_tran_id(self, use_magic_cookie=False):
        if use_magic_cookie:
            # Compatible with rfc3489, rfc5389 and rfc8489
            return struct.pack("!L", self.MAGIC_COOKIE) + os.urandom(12)
        else:
            # Compatible with rfc3489
            return os.urandom(16)

    def pack_stun_message(self, msg_type, tran_id, payload=b""):
        return struct.pack("!HH", msg_type, len(payload)) + tran_id + payload

    def unpack_stun_message(self, data):
        msg_type, msg_length = struct.unpack("!HH", data[:4])
        tran_id = data[4:20]
        payload = data[20:20 + msg_length]
        return msg_type, tran_id, payload

    def get_mapped_addr(self, payload):
        while payload:
            attrib_type, attrib_length = struct.unpack("!HH", payload[:4])
            attrib_value = payload[4:4 + attrib_length]
            payload = payload[4 + attrib_length:]
            if attrib_type == self.ATTRIB_MAPPED_ADDRESS:
                _, family, port = struct.unpack("!BBH", attrib_value[:4])
                if family == self.FAMILY_IPV4:
                    ip = socket.inet_ntoa(attrib_value[4:8])
                    return ip, port
            elif attrib_type == self.ATTRIB_XOR_MAPPED_ADDRESS:
                # rfc5389 and rfc8489
                _, family, xor_port = struct.unpack("!BBH", attrib_value[:4])
                if family == self.FAMILY_IPV4:
                    xor_iip, = struct.unpack("!L", attrib_value[4:8])
                    ip = socket.inet_ntoa(
                        struct.pack("!L", self.MAGIC_COOKIE ^ xor_iip))
                    port = (self.MAGIC_COOKIE >> 16) ^ xor_port
                    return ip, port
        return None

    def tcp_test(self, stun_host, source_ip, source_port, timeout=1):
        # rfc5389 and rfc8489 only
        self.logger.debug("Trying TCP STUN: %s" % stun_host)
        tran_id = self.random_tran_id(use_magic_cookie=True)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if 'SO_REUSEPORT' in dir(socket):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.settimeout(timeout)
            sock.bind((source_ip, source_port))
            sock.connect((stun_host, self.STUN_PORT))
            data = self.pack_stun_message(self.BIND_REQUEST, tran_id)
            sock.sendall(data)
            buf = sock.recv(self.MTU)
            msg_type, msg_id, payload = self.unpack_stun_message(buf)
            if tran_id == msg_id and msg_type == self.BIND_RESPONSE:
                source_addr = sock.getsockname()
                mapped_addr = self.get_mapped_addr(payload)
                ret = source_addr, mapped_addr
                self.logger.debug("(TCP) %s says: %s" %
                                  (stun_host, mapped_addr))
            else:
                ret = None
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        except Exception as e:
            self.logger.debug("%s: %s" % (e.__class__.__name__, e))
            sock.close()
            ret = None
        return ret

    def udp_test(self,
                 stun_host,
                 source_ip,
                 source_port,
                 change_ip=False,
                 change_port=False,
                 timeout=1,
                 repeat=3):
        # Note:
        #     Assuming STUN is being multiplexed with other protocols,
        #     the packet must be inspected to check if it is a STUN packet.
        self.logger.debug("Trying UDP STUN: %s (change ip:%d/port:%d)" %
                          (stun_host, change_ip, change_port))
        time_start = time.time()
        tran_id = self.random_tran_id()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if 'SO_REUSEPORT' in dir(socket):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.settimeout(timeout)
            sock.bind((source_ip, source_port))
            flags = 0
            if change_ip:
                flags |= self.CHANGE_IP
            if change_port:
                flags |= self.CHANGE_PORT
            if flags:
                payload = struct.pack("!HHL", self.ATTRIB_CHANGE_REQUEST, 0x4,
                                      flags)
                data = self.pack_stun_message(self.BIND_REQUEST, tran_id,
                                              payload)
            else:
                data = self.pack_stun_message(self.BIND_REQUEST, tran_id)
            # Send packets repeatedly to avoid packet loss.
            for _ in range(repeat):
                sock.sendto(data, (stun_host, self.STUN_PORT))
            while True:
                time_left = time_start + timeout - time.time()
                if time_left <= 0:
                    raise socket.timeout("timed out")
                sock.settimeout(time_left)
                buf, recv_addr = sock.recvfrom(self.MTU)
                recv_host, recv_port = recv_addr
                # check STUN packet
                if len(buf) < 20:
                    continue
                msg_type, msg_id, payload = self.unpack_stun_message(buf)
                if tran_id != msg_id or msg_type != self.BIND_RESPONSE:
                    continue
                source_addr = sock.getsockname()
                mapped_addr = self.get_mapped_addr(payload)
                ip_changed = (recv_host != self.STUN_PORT)
                port_changed = (recv_port != self.STUN_PORT)
                self.logger.debug("(UDP) %s says: %s" %
                                  (recv_addr, mapped_addr))
                return source_addr, mapped_addr, ip_changed, port_changed
        except Exception as e:
            self.logger.debug("%s: %s" % (e.__class__.__name__, e))
            return None
        finally:
            sock.close()

    def get_tcp_mapping(self, source_port):
        server_ip = first = self.stun_ip_tcp[0]
        while True:
            ret = self.tcp_test(server_ip, source_port)
            if ret is None:
                # server unavailable, put it at the end of the list
                self.stun_ip_tcp.append(self.stun_ip_tcp.pop(0))
                server_ip = self.stun_ip_tcp[0]
                if server_ip == first:
                    raise Exception(
                        "No public STUN server is avaliable. Please check your Internet connection."
                    )
            else:
                source_addr, mapped_addr = ret
                return source_addr, mapped_addr

    def get_udp_mapping(self, source_ip, source_port):
        server_ip = first = self.stun_ip_udp[0]
        while True:
            ret = self.udp_test(server_ip, source_ip, source_port)
            if ret is None:
                # server unavailable, put it at the end of the list
                self.stun_ip_udp.append(self.stun_ip_udp.pop(0))
                server_ip = self.stun_ip_udp[0]
                if server_ip == first:
                    raise Exception(
                        "No public STUN server is avaliable. Please check your Internet connection."
                    )
            else:
                source_addr, mapped_addr, ip_changed, port_changed = ret
                return source_addr, mapped_addr

    def check_nat_type(self, source_ip, source_port=0):
        # Like classic STUN (rfc3489). Detect NAT behavior for UDP.
        # Modified from rfc3489. Requires at least two STUN servers.
        ret_test1_1 = None
        ret_test1_2 = None
        ret_test2 = None
        ret_test3 = None
        if source_port == 0:
            source_port = self.get_free_port(udp=True)
        self.logger.info(
            "Checking NAT type for UDP with source ip %s, source port %s" %
            (source_ip, source_port))

        for server_ip in self.stun_ip_udp:
            ret = self.udp_test(server_ip,
                                source_ip,
                                source_port,
                                change_ip=False,
                                change_port=False)
            if ret is None:
                self.logger.debug("No response. Trying another STUN server...")
                continue
            if ret_test1_1 is None:
                ret_test1_1 = ret
                continue
            ret_test1_2 = ret
            ret = self.udp_test(server_ip,
                                source_ip,
                                source_port,
                                change_ip=True,
                                change_port=True)
            if ret is not None:
                source_addr, mapped_addr, ip_changed, port_changed = ret
                if not ip_changed or not port_changed:
                    self.logger.debug(
                        "Trying another STUN server because current server do not have another available IP or port..."
                    )
                    continue
            ret_test2 = ret
            ret_test3 = self.udp_test(server_ip,
                                      source_ip,
                                      source_port,
                                      change_ip=False,
                                      change_port=True)
            break
        else:
            raise Exception(
                "UDP Blocked or not enough STUN servers available.")

        source_addr_1_1, mapped_addr_1_1, _, _ = ret_test1_1
        source_addr_1_2, mapped_addr_1_2, _, _ = ret_test1_2
        if mapped_addr_1_1 != mapped_addr_1_2:
            return StunClient.NAT_SYMMETRIC
        if source_addr_1_1 == mapped_addr_1_1:
            if ret_test2 is not None:
                return StunClient.NAT_OPEN_INTERNET
            else:
                return StunClient.NAT_SYM_UDP_FIREWALL
        else:
            if ret_test2 is not None:
                return StunClient.NAT_FULL_CONE
            else:
                if ret_test3 is not None:
                    return StunClient.NAT_RESTRICTED
                else:
                    return StunClient.NAT_PORT_RESTRICTED

    def check_nat_type_return_txt(self, source_ip, source_port=0):
        nat_type = self.check_nat_type(source_ip, source_port)
        return self.NAT_TYPE_MAP.get(nat_type, "Unknown")

    def is_tcp_cone(self, source_port=0):
        # Detect NAT behavior for TCP. Requires at least three STUN servers for accuracy.
        if source_port == 0:
            source_port = self.get_free_port()
        mapped_addr_first = None
        count = 0
        for server_ip in self.stun_ip_tcp:
            if count >= 3:
                return True
            ret = self.tcp_test(server_ip, source_port)
            if ret is not None:
                source_addr, mapped_addr = ret
                if mapped_addr_first is not None and mapped_addr != mapped_addr_first:
                    return False
                mapped_addr_first = ret[1]
                count += 1
        raise Exception("Not enough STUN servers available.")


def get_args():
    parser = argparse.ArgumentParser(
        description='check nat type by stun server')
    parser.add_argument("-s",
                        "--source_ips",
                        nargs="*",
                        default="0.0.0.0",
                        help="source ip for client")
    parser.add_argument("-p",
                        "--source_port",
                        default=0,
                        help="source port for client")
    parser.add_argument(
        "-i",
        "--interface",
        default=None,
        help="source interface for client, support wild card, e.g. ppp*")
    parser.add_argument('-v', action='store_true', help='Enable info logging')
    parser.add_argument('-vv',
                        action='store_true',
                        help='Enable debug logging')
    args = parser.parse_args()
    return args


def main():
    args = get_args()
    log_level = Logger.WARNING
    if args.v:
        log_level = Logger.INFO
    if args.vv:
        log_level = Logger.DEBUG
    source_ips = set()
    iface_map = dict()
    if args.interface:
        ifaces = get_network_interfaces(args.interface)
        if len(ifaces) == 0:
            raise Exception("No network interface found for %s" %
                            args.interface)
        for iface in ifaces:
            ip = get_ip_address(iface)
            iface_map[ip] = iface
            source_ips.add(ip)
    else:
        if isinstance(args.source_ips, str):
            source_ips.add(args.source_ips)
        else:
            source_ips = set(args.source_ips)
    for source_ip in source_ips:
        try:
            ip = ipaddress.ip_address(source_ip)
            #if not ip.is_private:
            #    print("IP address is public: %s, skip check nat type" %
            #          source_ip)
            #    source_ips.pop(source_ip)
        except ValueError:
            raise Exception("Invalid IP address: %s" % source_ip)

    stun_client = StunClient(log_level=log_level)

    def run(source_ip, source_port):
        nat_type_txt = stun_client.check_nat_type_return_txt(
            source_ip, source_port)
        print("%s NAT Type: [ %s ]" %
              (iface_map.get(source_ip, source_ip), nat_type_txt))

    try:
        ts = []
        for source_ip in source_ips:
            t = threading.Thread(target=run,
                                 args=(source_ip, args.source_port))
            t.start()
        for t in ts:
            t.join()
    except KeyboardInterrupt:
        print("\nExiting...\n")


if __name__ == '__main__':
    main()
