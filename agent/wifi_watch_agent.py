import concurrent.futures
import errno
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
import tkinter as tk
from tkinter import messagebox

import psutil
import requests

from zeroconf import (
    IPVersion,
    ServiceBrowser,
    ServiceListener,
    Zeroconf,
)


# ============================================================
# WIFI WATCH AGENT
# ============================================================

APP_VERSION = "0.2.0"

# ============================================================
# IMPORTANT
#
# Use the SAME Supabase project URL and sb_publishable_ key
# that you use on the WiFi Watch website.
#
# NEVER put:
#   sb_secret_
#   service_role
#   database password
#
# inside this application.
# ============================================================

SUPABASE_URL = "https://ephdcwogebxfsidytmrj.supabase.co"
SUPABASE_KEY = "sb_publishable_L9TUAFyJ_S0l81UDNi8imw_FVTYm4cI"


SCAN_INTERVAL = 30
REQUEST_TIMEOUT = 20

MAX_WORKERS = 80

# We allow the real subnet up to 1024 addresses.
# Very large enterprise networks are restricted to the
# local /24 to avoid accidentally scanning huge ranges.
MAX_NETWORK_ADDRESSES = 1024


# ============================================================
# COMMON SERVICES
#
# This is intentionally a LIMITED TCP scan.
# It is not an exploit scanner.
# ============================================================

TCP_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    631: "IPP",
    1883: "MQTT",
    3389: "RDP",
    5000: "HTTP-alt",
    5001: "HTTPS-alt",
    7000: "AirPlay",
    8000: "HTTP-alt",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9100: "RAW-Printer",
    32400: "Plex",
    62078: "Apple-Sync",
}


# Fallback mDNS service types.
# v0.2.0 also tries to discover additional service types
# dynamically using DNS-SD.

DEFAULT_MDNS_TYPES = {
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_workstation._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_printer._tcp.local.",
    "_hap._tcp.local.",
    "_smb._tcp.local.",
    "_ssh._tcp.local.",
    "_device-info._tcp.local.",
    "_companion-link._tcp.local.",
    "_sleep-proxy._udp.local.",
}


REFUSED_CODES = {
    errno.ECONNREFUSED,
    61,
    111,
    10061,
}


# ============================================================
# APPLICATION STORAGE
# ============================================================

def get_app_folder():

    system = platform.system()

    if system == "Windows":

        base = Path(
            os.getenv(
                "APPDATA",
                Path.home()
            )
        )

        folder = (
            base
            / "WiFiWatch"
        )

    elif system == "Darwin":

        folder = (
            Path.home()
            / "Library"
            / "Application Support"
            / "WiFiWatch"
        )

    else:

        folder = (
            Path.home()
            / ".config"
            / "WiFiWatch"
        )

    folder.mkdir(
        parents=True,
        exist_ok=True
    )

    return folder


APP_FOLDER = get_app_folder()

CONFIG_FILE = (
    APP_FOLDER
    / "agent.json"
)

LOG_FILE = (
    APP_FOLDER
    / "agent.log"
)


# ============================================================
# LOGGING
# ============================================================

def log(message):

    timestamp = time.strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    line = (
        f"[{timestamp}] "
        f"{message}"
    )

    print(line)

    try:

        with open(
            LOG_FILE,
            "a",
            encoding="utf-8"
        ) as file:

            file.write(
                line + "\n"
            )

    except Exception:
        pass


# ============================================================
# CONFIG
# ============================================================

def load_config():

    if not CONFIG_FILE.exists():
        return {}

    try:

        with open(
            CONFIG_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(
                file
            )

    except Exception as exc:

        log(
            f"Config load error: {exc}"
        )

        return {}


def save_config(data):

    with open(
        CONFIG_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=2
        )

    if os.name != "nt":

        try:

            os.chmod(
                CONFIG_FILE,
                0o600
            )

        except Exception:
            pass


def delete_config():

    try:

        if CONFIG_FILE.exists():

            CONFIG_FILE.unlink()

    except Exception as exc:

        log(
            f"Config delete error: {exc}"
        )


# ============================================================
# SUPABASE RPC
# ============================================================

def rpc(
    function_name,
    payload
):

    url = (
        f"{SUPABASE_URL}"
        f"/rest/v1/rpc/"
        f"{function_name}"
    )

    headers = {
        "apikey":
            SUPABASE_KEY,

        "Content-Type":
            "application/json",
    }

    response = requests.post(
        url,
        headers=headers,
        json=payload,
        timeout=REQUEST_TIMEOUT
    )

    if not response.ok:

        try:

            details = response.json()

        except Exception:

            details = response.text

        raise RuntimeError(
            f"{response.status_code}: "
            f"{details}"
        )

    if not response.content:
        return None

    return response.json()


# ============================================================
# PAIRING
# ============================================================

def claim_pairing_code(code):

    result = rpc(
        "claim_pairing_code",
        {
            "p_code":
                code.strip(),

            "p_name":
                "WiFi Watch Agent",

            "p_platform":
                platform.system(),

            "p_hostname":
                socket.gethostname(),

            "p_version":
                APP_VERSION,
        }
    )

    if not result:

        raise RuntimeError(
            "Pairing failed."
        )

    for required in (
        "agent_id",
        "agent_secret",
        "network_id"
    ):

        if required not in result:

            raise RuntimeError(
                "Invalid pairing response."
            )

    config = {
        "agent_id":
            result["agent_id"],

        "agent_secret":
            result["agent_secret"],

        "network_id":
            result["network_id"],
    }

    save_config(
        config
    )

    log(
        "Agent paired successfully."
    )

    return config


# ============================================================
# HEARTBEAT
# ============================================================

def heartbeat(config):

    return rpc(
        "agent_heartbeat",
        {
            "p_agent_id":
                config["agent_id"],

            "p_agent_secret":
                config["agent_secret"],

            "p_version":
                APP_VERSION,
        }
    )


# ============================================================
# COMMAND HELPER
# ============================================================

def get_command(
    name,
    candidates
):

    found = shutil.which(
        name
    )

    if found:
        return found

    for candidate in candidates:

        if os.path.exists(
            candidate
        ):

            return candidate

    return name


# ============================================================
# MAC ADDRESS HELPERS
# ============================================================

def normalize_mac(mac):

    if not mac:
        return None

    value = (
        str(mac)
        .strip()
        .lower()
        .replace(
            "-",
            ":"
        )
    )

    parts = value.split(
        ":"
    )

    if len(parts) != 6:
        return None

    normalized = []

    try:

        for part in parts:

            if (
                len(part) < 1
                or
                len(part) > 2
            ):

                return None

            number = int(
                part,
                16
            )

            normalized.append(
                f"{number:02x}"
            )

    except Exception:

        return None

    return ":".join(
        normalized
    )


def valid_mac(mac):

    mac = normalize_mac(
        mac
    )

    if not mac:
        return False

    if mac in (
        "00:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff"
    ):

        return False

    try:

        first_byte = int(
            mac.split(":")[0],
            16
        )

        # multicast address
        if first_byte & 1:
            return False

    except Exception:

        return False

    return True


def is_private_mac(mac):

    mac = normalize_mac(
        mac
    )

    if not mac:
        return False

    try:

        first_byte = int(
            mac.split(":")[0],
            16
        )

        # Locally administered bit
        return bool(
            first_byte & 2
        )

    except Exception:

        return False


# ============================================================
# NETWORK INFORMATION
# ============================================================

def get_primary_local_ip():

    # First try normal route selection.

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    try:

        sock.connect(
            (
                "1.1.1.1",
                80
            )
        )

        ip = (
            sock.getsockname()[0]
        )

        if ip:
            return ip

    except Exception:
        pass

    finally:

        sock.close()

    # Internet may be unavailable.
    # Find a private IPv4 interface.

    for addresses in (
        psutil
        .net_if_addrs()
        .values()
    ):

        for address in addresses:

            if (
                address.family
                == socket.AF_INET
            ):

                try:

                    ip = (
                        ipaddress
                        .ip_address(
                            address.address
                        )
                    )

                    if (
                        ip.is_private
                        and
                        not ip.is_loopback
                    ):

                        return str(ip)

                except Exception:
                    pass

    raise RuntimeError(
        "Could not determine local IPv4 address."
    )


def get_network_details():

    local_ip = (
        get_primary_local_ip()
    )

    interface_name = None
    netmask = None
    own_mac = None

    interfaces = (
        psutil.net_if_addrs()
    )

    for (
        name,
        addresses
    ) in interfaces.items():

        matches_ip = False

        for address in addresses:

            if (
                address.family
                == socket.AF_INET
                and
                address.address
                == local_ip
            ):

                interface_name = name

                netmask = (
                    address.netmask
                )

                matches_ip = True

                break

        if not matches_ip:
            continue

        for address in addresses:

            if (
                address.family
                == psutil.AF_LINK
            ):

                own_mac = normalize_mac(
                    address.address
                )

                break

        break

    if not netmask:

        netmask = (
            "255.255.255.0"
        )

    network = ipaddress.ip_network(
        f"{local_ip}/{netmask}",
        strict=False
    )

    if (
        network.num_addresses
        > MAX_NETWORK_ADDRESSES
    ):

        # Avoid scanning a massive corporate subnet.
        # Scan the local /24 segment instead.

        network = ipaddress.ip_network(
            f"{local_ip}/24",
            strict=False
        )

    log(
        "Network detected: "
        f"interface={interface_name}, "
        f"ip={local_ip}, "
        f"network={network}, "
        f"mac={own_mac}"
    )

    return {
        "local_ip":
            local_ip,

        "interface":
            interface_name,

        "network":
            network,

        "own_mac":
            own_mac,
    }


# ============================================================
# DISCOVERY RESULT HELPERS
# ============================================================

def new_device_record(ip):

    return {
        "ip":
            str(ip),

        "mac":
            None,

        "hostname":
            None,

        "vendor":
            None,

        "methods":
            set(),

        "open_ports":
            set(),
    }


def add_discovery(
    discovered,
    network,
    ip,
    method,
    hostname=None,
    mac=None
):

    try:

        address = ipaddress.ip_address(
            str(ip)
        )

    except Exception:
        return

    if (
        address.version != 4
        or
        address not in network
    ):

        return

    key = str(
        address
    )

    if key not in discovered:

        discovered[key] = (
            new_device_record(
                key
            )
        )

    discovered[key][
        "methods"
    ].add(
        method
    )

    if hostname:

        clean_hostname = (
            str(hostname)
            .strip()
            .rstrip(".")
        )

        if clean_hostname:

            discovered[key][
                "hostname"
            ] = clean_hostname

    normalized = normalize_mac(
        mac
    )

    if valid_mac(
        normalized
    ):

        discovered[key][
            "mac"
        ] = normalized


# ============================================================
# ARP / NEIGHBOR CACHE SEED
# ============================================================

def seed_neighbor(ip):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.settimeout(
        0.15
    )

    try:

        # Sending one local packet makes the OS
        # attempt ARP resolution for the destination.

        sock.sendto(
            b"\x00",
            (
                str(ip),
                9
            )
        )

    except Exception:
        pass

    finally:

        sock.close()


# ============================================================
# ICMP DISCOVERY
# ============================================================

def ping_host(ip):

    ip = str(
        ip
    )

    system = platform.system()

    creation_flags = 0

    if system == "Darwin":

        binary = get_command(
            "ping",
            [
                "/sbin/ping",
                "/usr/bin/ping"
            ]
        )

        command = [
            binary,
            "-c",
            "1",
            "-W",
            "700",
            ip
        ]

    elif system == "Windows":

        binary = get_command(
            "ping",
            []
        )

        command = [
            binary,
            "-n",
            "1",
            "-w",
            "700",
            ip
        ]

        if hasattr(
            subprocess,
            "CREATE_NO_WINDOW"
        ):

            creation_flags = (
                subprocess.CREATE_NO_WINDOW
            )

    else:

        binary = get_command(
            "ping",
            [
                "/usr/bin/ping",
                "/bin/ping"
            ]
        )

        command = [
            binary,
            "-c",
            "1",
            "-W",
            "1",
            ip
        ]

    try:

        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            creationflags=creation_flags
        )

        if result.returncode == 0:

            return ip

    except Exception:
        pass

    return None


# ============================================================
# TCP DISCOVERY
# ============================================================

def tcp_probe_host(ip):

    ip = str(
        ip
    )

    alive = False
    open_ports = []

    for port in TCP_SERVICES:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(
            0.18
        )

        try:

            result = sock.connect_ex(
                (
                    ip,
                    port
                )
            )

            if result == 0:

                alive = True

                open_ports.append(
                    port
                )

            elif result in REFUSED_CODES:

                # A fast "connection refused" is also
                # evidence that a host answered us.

                alive = True

        except Exception:
            pass

        finally:

            try:
                sock.close()

            except Exception:
                pass

    return (
        ip,
        alive,
        open_ports
    )


# ============================================================
# MACOS NEIGHBOR TABLE
# ============================================================

def get_macos_neighbors():

    binary = get_command(
        "arp",
        [
            "/usr/sbin/arp",
            "/sbin/arp"
        ]
    )

    output = subprocess.check_output(
        [
            binary,
            "-an"
        ],
        text=True,
        stderr=subprocess.DEVNULL
    )

    result = {}

    # macOS may print:
    #
    # 8:3a:2:b:4:10
    #
    # instead of:
    #
    # 08:3a:02:0b:04:10

    pattern = re.compile(
        r"\((\d+\.\d+\.\d+\.\d+)\)"
        r"\s+at\s+"
        r"([0-9A-Fa-f:]+)"
    )

    for (
        ip,
        raw_mac
    ) in pattern.findall(
        output
    ):

        mac = normalize_mac(
            raw_mac
        )

        if valid_mac(
            mac
        ):

            result[ip] = mac

    return result


# ============================================================
# WINDOWS NEIGHBOR TABLE
# ============================================================

def get_windows_neighbors():

    binary = get_command(
        "arp",
        []
    )

    flags = 0

    if hasattr(
        subprocess,
        "CREATE_NO_WINDOW"
    ):

        flags = (
            subprocess.CREATE_NO_WINDOW
        )

    output = subprocess.check_output(
        [
            binary,
            "-a"
        ],
        text=True,
        stderr=subprocess.DEVNULL,
        creationflags=flags
    )

    result = {}

    pattern = re.compile(
        r"(\d+\.\d+\.\d+\.\d+)"
        r"\s+"
        r"([0-9A-Fa-f-]{11,17})"
    )

    for (
        ip,
        raw_mac
    ) in pattern.findall(
        output
    ):

        mac = normalize_mac(
            raw_mac
        )

        if valid_mac(
            mac
        ):

            result[ip] = mac

    return result


# ============================================================
# LINUX NEIGHBOR TABLE
# ============================================================

def get_linux_neighbors():

    result = {}

    ip_binary = get_command(
        "ip",
        [
            "/usr/sbin/ip",
            "/usr/bin/ip",
            "/sbin/ip"
        ]
    )

    try:

        output = subprocess.check_output(
            [
                ip_binary,
                "neigh",
                "show"
            ],
            text=True,
            stderr=subprocess.DEVNULL
        )

        pattern = re.compile(
            r"(\d+\.\d+\.\d+\.\d+)"
            r".*?\slladdr\s"
            r"([0-9A-Fa-f:]+)"
        )

        for (
            ip,
            raw_mac
        ) in pattern.findall(
            output
        ):

            mac = normalize_mac(
                raw_mac
            )

            if valid_mac(
                mac
            ):

                result[ip] = mac

        if result:
            return result

    except Exception:
        pass

    arp_binary = get_command(
        "arp",
        [
            "/usr/sbin/arp",
            "/usr/bin/arp"
        ]
    )

    try:

        output = subprocess.check_output(
            [
                arp_binary,
                "-an"
            ],
            text=True,
            stderr=subprocess.DEVNULL
        )

        pattern = re.compile(
            r"\((\d+\.\d+\.\d+\.\d+)\)"
            r"\s+at\s+"
            r"([0-9A-Fa-f:]+)"
        )

        for (
            ip,
            raw_mac
        ) in pattern.findall(
            output
        ):

            mac = normalize_mac(
                raw_mac
            )

            if valid_mac(
                mac
            ):

                result[ip] = mac

    except Exception:
        pass

    return result


def get_neighbor_table():

    system = platform.system()

    try:

        if system == "Darwin":

            result = (
                get_macos_neighbors()
            )

        elif system == "Windows":

            result = (
                get_windows_neighbors()
            )

        else:

            result = (
                get_linux_neighbors()
            )

        log(
            "Neighbor table: "
            f"{len(result)} device(s)"
        )

        return result

    except Exception as exc:

        log(
            f"Neighbor table error: {exc}"
        )

        return {}


# ============================================================
# SSDP / UPNP DISCOVERY
# ============================================================

def discover_ssdp():

    found = set()

    request = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
        socket.IPPROTO_UDP
    )

    try:

        sock.settimeout(
            0.4
        )

        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_TTL,
            2
        )

        for _ in range(2):

            try:

                sock.sendto(
                    request,
                    (
                        "239.255.255.250",
                        1900
                    )
                )

            except Exception:
                pass

        deadline = (
            time.time() + 3.0
        )

        while (
            time.time()
            < deadline
        ):

            try:

                _data, address = (
                    sock.recvfrom(
                        65535
                    )
                )

                found.add(
                    address[0]
                )

            except socket.timeout:

                continue

            except Exception:

                break

    finally:

        sock.close()

    log(
        "SSDP discovery: "
        f"{len(found)} device(s)"
    )

    return found


# ============================================================
# MDNS / BONJOUR
# ============================================================

class ServiceTypeListener(
    ServiceListener
):

    def __init__(
        self,
        result_set
    ):

        self.result_set = (
            result_set
        )

        self.lock = (
            threading.Lock()
        )

    def add_service(
        self,
        zeroconf,
        service_type,
        name
    ):

        value = (
            str(name)
            .strip()
        )

        if (
            value.startswith("_")
            and
            value.endswith(".local.")
        ):

            with self.lock:

                self.result_set.add(
                    value
                )

    def update_service(
        self,
        zeroconf,
        service_type,
        name
    ):
        pass

    def remove_service(
        self,
        zeroconf,
        service_type,
        name
    ):
        pass


class DeviceServiceListener(
    ServiceListener
):

    def __init__(
        self,
        result_dict
    ):

        self.result_dict = (
            result_dict
        )

        self.lock = (
            threading.Lock()
        )

    def add_service(
        self,
        zeroconf,
        service_type,
        name
    ):

        self._read(
            zeroconf,
            service_type,
            name
        )

    def update_service(
        self,
        zeroconf,
        service_type,
        name
    ):

        self._read(
            zeroconf,
            service_type,
            name
        )

    def remove_service(
        self,
        zeroconf,
        service_type,
        name
    ):
        pass

    def _read(
        self,
        zeroconf,
        service_type,
        name
    ):

        try:

            info = (
                zeroconf
                .get_service_info(
                    service_type,
                    name,
                    timeout=700
                )
            )

            if not info:
                return

            hostname = (
                info.server
                or
                name
            )

            hostname = (
                str(hostname)
                .rstrip(".")
            )

            addresses = (
                info.parsed_addresses(
                    IPVersion.V4Only
                )
            )

            with self.lock:

                for ip in addresses:

                    self.result_dict[ip] = {
                        "hostname":
                            hostname,

                        "service_type":
                            service_type,
                    }

        except Exception:
            pass


def discover_mdns():

    results = {}

    service_types = set(
        DEFAULT_MDNS_TYPES
    )

    zeroconf = None

    try:

        zeroconf = Zeroconf(
            ip_version=
                IPVersion.V4Only
        )

        # ----------------------------------------------------
        # First discover DNS-SD service TYPES.
        # ----------------------------------------------------

        type_listener = (
            ServiceTypeListener(
                service_types
            )
        )

        type_browser = (
            ServiceBrowser(
                zeroconf,
                "_services._dns-sd._udp.local.",
                type_listener
            )
        )

        time.sleep(
            2.0
        )

        try:

            type_browser.cancel()

        except Exception:
            pass

        # Limit unexpected huge service lists.

        discovered_types = sorted(
            service_types
        )[:50]

        log(
            "mDNS service types: "
            f"{len(discovered_types)}"
        )

        # ----------------------------------------------------
        # Now browse devices advertising those services.
        # ----------------------------------------------------

        device_listener = (
            DeviceServiceListener(
                results
            )
        )

        browsers = []

        for service_type in (
            discovered_types
        ):

            try:

                browser = (
                    ServiceBrowser(
                        zeroconf,
                        service_type,
                        device_listener
                    )
                )

                browsers.append(
                    browser
                )

            except Exception:
                pass

        time.sleep(
            4.0
        )

        for browser in browsers:

            try:

                browser.cancel()

            except Exception:
                pass

    except Exception as exc:

        log(
            f"mDNS discovery error: {exc}"
        )

    finally:

        if zeroconf:

            try:

                zeroconf.close()

            except Exception:
                pass

    log(
        "mDNS discovery: "
        f"{len(results)} device(s)"
    )

    return results


# ============================================================
# DEVICE TYPE
# ============================================================

def infer_device_type(
    hostname,
    ports,
    methods
):

    value = (
        hostname
        or ""
    ).lower()

    port_set = set(
        ports
    )

    if (
        631 in port_set
        or
        9100 in port_set
        or
        "printer" in value
    ):

        return "printer"

    if (
        "iphone" in value
        or
        "ipad" in value
        or
        "android" in value
        or
        "phone" in value
    ):

        return "mobile"

    if (
        "apple-tv" in value
        or
        "appletv" in value
        or
        "chromecast" in value
        or
        "roku" in value
        or
        "television" in value
        or
        "smart-tv" in value
    ):

        return "media"

    if (
        554 in port_set
        and
        80 in port_set
    ):

        return "camera_or_media"

    if (
        445 in port_set
        or
        139 in port_set
    ):

        return "computer_or_nas"

    if (
        32400 in port_set
    ):

        return "media_server"

    if (
        62078 in port_set
    ):

        return "apple_device"

    if (
        22 in port_set
    ):

        return "computer_or_server"

    if (
        "airplay" in methods
        or
        "mdns" in methods
    ):

        return "network_device"

    return "unknown"


# ============================================================
# SECURITY ASSESSMENT
# ============================================================

def build_security_assessment(
    ports
):

    ports = set(
        ports
    )

    findings = []

    # --------------------------------------------------------
    # Higher concern:
    # clear-text remote/admin protocols.
    # --------------------------------------------------------

    if 23 in ports:

        findings.append({
            "severity":
                "warning",

            "title":
                "Telnet service reachable",

            "detail":
                (
                    "Telnet is a clear-text remote "
                    "access protocol. Confirm that "
                    "this service is intentionally "
                    "enabled."
                ),

            "port":
                23,
        })

    if 21 in ports:

        findings.append({
            "severity":
                "warning",

            "title":
                "FTP service reachable",

            "detail":
                (
                    "FTP can transmit credentials "
                    "and data without encryption. "
                    "Confirm that this service is "
                    "required and protected."
                ),

            "port":
                21,
        })

    # --------------------------------------------------------
    # Review items.
    # These are NOT automatically vulnerabilities.
    # --------------------------------------------------------

    if 80 in ports:

        findings.append({
            "severity":
                "review",

            "title":
                "HTTP service reachable",

            "detail":
                (
                    "An unencrypted HTTP service is "
                    "reachable on the local network. "
                    "This may be normal for routers, "
                    "printers or IoT devices."
                ),

            "port":
                80,
        })

    if 445 in ports:

        findings.append({
            "severity":
                "review",

            "title":
                "SMB file-sharing service reachable",

            "detail":
                (
                    "SMB is reachable from the local "
                    "network. Confirm that file "
                    "sharing is intentionally enabled."
                ),

            "port":
                445,
        })

    if 3389 in ports:

        findings.append({
            "severity":
                "review",

            "title":
                "Remote Desktop service reachable",

            "detail":
                (
                    "RDP is reachable from the local "
                    "network. Confirm that remote "
                    "desktop access is required."
                ),

            "port":
                3389,
        })

    if 1883 in ports:

        findings.append({
            "severity":
                "review",

            "title":
                "MQTT service reachable",

            "detail":
                (
                    "MQTT is reachable on its common "
                    "non-TLS port. Verify authentication "
                    "and encryption configuration."
                ),

            "port":
                1883,
        })

    if 554 in ports:

        findings.append({
            "severity":
                "review",

            "title":
                "RTSP media service reachable",

            "detail":
                (
                    "An RTSP media stream endpoint "
                    "appears reachable. Confirm that "
                    "access is restricted as intended."
                ),

            "port":
                554,
        })

    if 9100 in ports:

        findings.append({
            "severity":
                "review",

            "title":
                "Raw printer service reachable",

            "detail":
                (
                    "Raw TCP printing is reachable "
                    "on port 9100. This can be normal "
                    "for network printers."
                ),

            "port":
                9100,
        })

    severities = {
        item["severity"]
        for item in findings
    }

    if "warning" in severities:

        status = "warning"

    elif "review" in severities:

        status = "review"

    elif ports:

        status = (
            "no_obvious_issues"
        )

        findings.append({
            "severity":
                "info",

            "title":
                "No obvious risky service detected",

            "detail":
                (
                    "The limited local-network check "
                    "did not identify one of the "
                    "services currently flagged by "
                    "WiFi Watch. This does not prove "
                    "that the device is fully secure."
                ),
        })

    else:

        status = "unknown"

        findings.append({
            "severity":
                "info",

            "title":
                "Security status not determined",

            "detail":
                (
                    "The device was discovered, but "
                    "none of the limited TCP services "
                    "checked by WiFi Watch responded. "
                    "This does not mean the device is "
                    "secure or insecure."
                ),
        })

    return (
        status,
        findings
    )


# ============================================================
# SERVICE INFORMATION
# ============================================================

def build_services(
    open_ports
):

    services = []

    for port in sorted(
        open_ports
    ):

        services.append({
            "protocol":
                "tcp",

            "port":
                port,

            "name":
                TCP_SERVICES.get(
                    port,
                    "Unknown"
                ),
        })

    return services


# ============================================================
# FULL LOCAL NETWORK SCAN
# ============================================================

def scan_network():

    details = (
        get_network_details()
    )

    network = (
        details["network"]
    )

    local_ip = (
        details["local_ip"]
    )

    own_mac = (
        details["own_mac"]
    )

    hosts = list(
        network.hosts()
    )

    discovered = {}

    add_discovery(
        discovered,
        network,
        local_ip,
        "agent",
        hostname=
            socket.gethostname(),
        mac=
            own_mac
    )

    log(
        "================================================"
    )

    log(
        f"Starting WiFi Watch v{APP_VERSION} scan"
    )

    log(
        f"Scanning {len(hosts)} IPv4 addresses"
    )

    # ========================================================
    # PASS 1
    # Seed ARP / neighbor table
    # ========================================================

    log(
        "PASS 1: Neighbor discovery"
    )

    with (
        concurrent.futures
        .ThreadPoolExecutor(
            max_workers=
                MAX_WORKERS
        )
    ) as executor:

        list(
            executor.map(
                seed_neighbor,
                hosts
            )
        )

    # ========================================================
    # PASS 2
    # ICMP
    # ========================================================

    log(
        "PASS 2: ICMP discovery"
    )

    ping_hits = set()

    with (
        concurrent.futures
        .ThreadPoolExecutor(
            max_workers=
                MAX_WORKERS
        )
    ) as executor:

        futures = [
            executor.submit(
                ping_host,
                ip
            )
            for ip in hosts
        ]

        for future in (
            concurrent.futures
            .as_completed(
                futures
            )
        ):

            try:

                result = (
                    future.result()
                )

                if result:

                    ping_hits.add(
                        result
                    )

                    add_discovery(
                        discovered,
                        network,
                        result,
                        "icmp"
                    )

            except Exception:
                pass

    log(
        "ICMP: "
        f"{len(ping_hits)} response(s)"
    )

    # ========================================================
    # PASS 3
    # Limited TCP service discovery
    # ========================================================

    log(
        "PASS 3: TCP discovery"
    )

    tcp_live = 0

    with (
        concurrent.futures
        .ThreadPoolExecutor(
            max_workers=
                MAX_WORKERS
        )
    ) as executor:

        futures = [
            executor.submit(
                tcp_probe_host,
                ip
            )
            for ip in hosts
        ]

        for future in (
            concurrent.futures
            .as_completed(
                futures
            )
        ):

            try:

                (
                    ip,
                    alive,
                    open_ports
                ) = future.result()

                if alive:

                    tcp_live += 1

                    add_discovery(
                        discovered,
                        network,
                        ip,
                        "tcp"
                    )

                if (
                    ip in discovered
                    and
                    open_ports
                ):

                    discovered[ip][
                        "open_ports"
                    ].update(
                        open_ports
                    )

            except Exception:
                pass

    log(
        "TCP: "
        f"{tcp_live} host response(s)"
    )

    # ========================================================
    # PASS 4
    # SSDP / UPnP
    # ========================================================

    log(
        "PASS 4: SSDP / UPnP discovery"
    )

    for ip in (
        discover_ssdp()
    ):

        add_discovery(
            discovered,
            network,
            ip,
            "ssdp"
        )

    # ========================================================
    # PASS 5
    # mDNS / Bonjour
    # ========================================================

    log(
        "PASS 5: mDNS / Bonjour discovery"
    )

    mdns_results = (
        discover_mdns()
    )

    for (
        ip,
        info
    ) in mdns_results.items():

        add_discovery(
            discovered,
            network,
            ip,
            "mdns",
            hostname=
                info.get(
                    "hostname"
                )
        )

    # ========================================================
    # PASS 6
    # Give OS a moment to finish ARP resolution
    # ========================================================

    time.sleep(
        1.0
    )

    # ========================================================
    # PASS 7
    # Read the OS neighbor / ARP table
    # ========================================================

    log(
        "PASS 6: Reading ARP / neighbor table"
    )

    neighbors = (
        get_neighbor_table()
    )

    for (
        ip,
        mac
    ) in neighbors.items():

        add_discovery(
            discovered,
            network,
            ip,
            "arp",
            mac=mac
        )

    # ========================================================
    # SECOND TCP CHECK
    #
    # Some hosts only appeared through mDNS/ARP after our
    # first pass. Check their common services now.
    # ========================================================

    second_pass_ips = [
        ip
        for ip in discovered
        if not discovered[ip][
            "open_ports"
        ]
    ]

    with (
        concurrent.futures
        .ThreadPoolExecutor(
            max_workers=
                MAX_WORKERS
        )
    ) as executor:

        futures = [
            executor.submit(
                tcp_probe_host,
                ip
            )
            for ip in second_pass_ips
        ]

        for future in (
            concurrent.futures
            .as_completed(
                futures
            )
        ):

            try:

                (
                    ip,
                    _alive,
                    open_ports
                ) = future.result()

                if (
                    ip in discovered
                    and
                    open_ports
                ):

                    discovered[ip][
                        "open_ports"
                    ].update(
                        open_ports
                    )

                    discovered[ip][
                        "methods"
                    ].add(
                        "tcp"
                    )

            except Exception:
                pass

    # ========================================================
    # BUILD FINAL DEVICE DATA
    # ========================================================

    devices = []

    for ip in sorted(
        discovered.keys(),
        key=lambda value:
            ipaddress.ip_address(
                value
            )
    ):

        item = (
            discovered[ip]
        )

        mac = normalize_mac(
            item.get(
                "mac"
            )
        )

        if not valid_mac(
            mac
        ):

            mac = None

        hostname = (
            item.get(
                "hostname"
            )
        )

        methods = sorted(
            item.get(
                "methods",
                set()
            )
        )

        open_ports = sorted(
            item.get(
                "open_ports",
                set()
            )
        )

        services = (
            build_services(
                open_ports
            )
        )

        (
            security_status,
            security_findings
        ) = build_security_assessment(
            open_ports
        )

        device_type = (
            infer_device_type(
                hostname,
                open_ports,
                methods
            )
        )

        vendor = None

        if (
            mac
            and
            is_private_mac(mac)
        ):

            # Do not pretend this is the manufacturer.
            # It only tells us the address is locally
            # administered/randomized.

            vendor = (
                "Private/Randomized MAC"
            )

        device = {
            "ip":
                ip,

            "mac":
                mac,

            "hostname":
                hostname,

            "vendor":
                vendor,

            "device_type":
                device_type,

            "discovery_methods":
                methods,

            "open_ports":
                open_ports,

            "services":
                services,

            "security_status":
                security_status,

            "security_findings":
                security_findings,
        }

        devices.append(
            device
        )

    # ========================================================
    # LOG RESULTS
    # ========================================================

    log(
        "================================================"
    )

    log(
        f"FINAL DEVICE COUNT: "
        f"{len(devices)}"
    )

    for device in devices:

        log(
            "DEVICE | "
            f"IP={device['ip']} | "
            f"MAC={device['mac']} | "
            f"HOST={device['hostname']} | "
            f"TYPE={device['device_type']} | "
            f"METHODS={','.join(device['discovery_methods'])} | "
            f"PORTS={device['open_ports']} | "
            f"SECURITY={device['security_status']}"
        )

    log(
        "================================================"
    )

    return (
        devices,
        network,
        local_ip
    )


# ============================================================
# SYNC DEVICES
# ============================================================

def sync_devices(
    config,
    devices
):

    return rpc(
        "agent_sync_devices",
        {
            "p_agent_id":
                config["agent_id"],

            "p_agent_secret":
                config["agent_secret"],

            "p_devices":
                devices,
        }
    )


# ============================================================
# GUI
# ============================================================

class WiFiWatchApp:

    def __init__(self):

        self.root = tk.Tk()

        self.root.title(
            "WiFi Watch Agent"
        )

        self.root.geometry(
            "570x590"
        )

        self.root.minsize(
            500,
            500
        )

        self.root.configure(
            bg="#071017"
        )

        self.config = (
            load_config()
        )

        self.stop_event = (
            threading.Event()
        )

        self.monitor_thread = None

        self.scan_lock = (
            threading.Lock()
        )

        self.status_value = (
            tk.StringVar(
                value=
                    "Not connected"
            )
        )

        self.network_value = (
            tk.StringVar(
                value="—"
            )
        )

        self.device_value = (
            tk.StringVar(
                value="0"
            )
        )

        self.security_value = (
            tk.StringVar(
                value="—"
            )
        )

        self.scan_value = (
            tk.StringVar(
                value="Never"
            )
        )

        self.build_ui()

        if self.is_paired():

            self.show_connected()

            self.start_monitoring()

        else:

            self.show_pairing()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close
        )

    # ========================================================
    # BASIC LABEL
    # ========================================================

    def label(
        self,
        parent,
        text="",
        size=12,
        bold=False,
        color="#ffffff"
    ):

        return tk.Label(
            parent,
            text=text,
            bg="#071017",
            fg=color,
            font=(
                "Arial",
                size,
                (
                    "bold"
                    if bold
                    else "normal"
                )
            )
        )

    # ========================================================
    # PAIRED?
    # ========================================================

    def is_paired(self):

        return bool(
            self.config.get(
                "agent_id"
            )
            and
            self.config.get(
                "agent_secret"
            )
        )

    # ========================================================
    # MAIN WINDOW
    # ========================================================

    def build_ui(self):

        header = tk.Frame(
            self.root,
            bg="#071017"
        )

        header.pack(
            fill="x",
            padx=28,
            pady=(25, 10)
        )

        logo = tk.Label(
            header,
            text="⌁",
            bg="#35e79a",
            fg="#042116",
            font=(
                "Arial",
                22,
                "bold"
            ),
            width=2,
            height=1
        )

        logo.pack(
            side="left"
        )

        title_wrap = tk.Frame(
            header,
            bg="#071017"
        )

        title_wrap.pack(
            side="left",
            padx=12
        )

        self.label(
            title_wrap,
            "WiFi Watch Agent",
            18,
            True
        ).pack(
            anchor="w"
        )

        self.label(
            title_wrap,
            f"Version {APP_VERSION}",
            10,
            False,
            "#8da2af"
        ).pack(
            anchor="w"
        )

        self.body = tk.Frame(
            self.root,
            bg="#071017"
        )

        self.body.pack(
            fill="both",
            expand=True,
            padx=28,
            pady=15
        )

    def clear_body(self):

        for widget in (
            self.body
            .winfo_children()
        ):

            widget.destroy()

    # ========================================================
    # PAIRING SCREEN
    # ========================================================

    def show_pairing(self):

        self.clear_body()

        self.label(
            self.body,
            "Pair this computer",
            20,
            True
        ).pack(
            anchor="w",
            pady=(10, 6)
        )

        self.label(
            self.body,
            (
                "Generate a pairing code "
                "from the WiFi Watch website "
                "and enter it below."
            ),
            11,
            False,
            "#8da2af"
        ).pack(
            anchor="w",
            pady=(0, 22)
        )

        self.label(
            self.body,
            "PAIRING CODE",
            9,
            True,
            "#8da2af"
        ).pack(
            anchor="w"
        )

        self.code_entry = tk.Entry(
            self.body,
            bg="#101f29",
            fg="#ffffff",
            insertbackground=
                "#ffffff",
            relief="flat",
            font=(
                "Courier",
                15,
                "bold"
            )
        )

        self.code_entry.pack(
            fill="x",
            ipady=12,
            pady=(7, 15)
        )

        connect = tk.Button(
            self.body,
            text="Connect",
            bg="#35e79a",
            fg="#042116",
            activebackground=
                "#35e79a",
            relief="flat",
            font=(
                "Arial",
                12,
                "bold"
            ),
            command=self.pair
        )

        connect.pack(
            fill="x",
            ipady=9
        )

        self.pair_status = (
            self.label(
                self.body,
                "",
                10,
                False,
                "#ffbd67"
            )
        )

        self.pair_status.pack(
            pady=15
        )

        self.label(
            self.body,
            (
                "Only use WiFi Watch on networks "
                "you own or are authorized to manage."
            ),
            9,
            False,
            "#66808e"
        ).pack(
            side="bottom",
            pady=10
        )

    # ========================================================
    # PAIR
    # ========================================================

    def pair(self):

        code = (
            self.code_entry
            .get()
            .strip()
        )

        if not code:

            messagebox.showerror(
                "WiFi Watch",
                "Enter a pairing code."
            )

            return

        self.pair_status.config(
            text="Connecting..."
        )

        threading.Thread(
            target=
                self._pair_worker,
            args=(code,),
            daemon=True
        ).start()

    def _pair_worker(
        self,
        code
    ):

        try:

            config = (
                claim_pairing_code(
                    code
                )
            )

            self.config = config

            self.root.after(
                0,
                self._pair_success
            )

        except Exception as exc:

            log(
                f"Pairing error: {exc}"
            )

            self.root.after(
                0,
                lambda:
                    self._pair_error(
                        str(exc)
                    )
            )

    def _pair_success(self):

        messagebox.showinfo(
            "WiFi Watch",
            "Agent paired successfully."
        )

        self.show_connected()

        self.start_monitoring()

    def _pair_error(
        self,
        error
    ):

        self.pair_status.config(
            text="Pairing failed."
        )

        messagebox.showerror(
            "Pairing failed",
            error
        )

    # ========================================================
    # CONNECTED SCREEN
    # ========================================================

    def show_connected(self):

        self.clear_body()

        self.label(
            self.body,
            "● Connected",
            13,
            True,
            "#35e79a"
        ).pack(
            anchor="w",
            pady=(8, 20)
        )

        card = tk.Frame(
            self.body,
            bg="#101f29"
        )

        card.pack(
            fill="x"
        )

        rows = [
            (
                "Status",
                self.status_value
            ),
            (
                "Network",
                self.network_value
            ),
            (
                "Devices detected",
                self.device_value
            ),
            (
                "Security",
                self.security_value
            ),
            (
                "Last scan",
                self.scan_value
            ),
        ]

        for (
            title,
            variable
        ) in rows:

            row = tk.Frame(
                card,
                bg="#101f29"
            )

            row.pack(
                fill="x",
                padx=18,
                pady=10
            )

            tk.Label(
                row,
                text=title,
                bg="#101f29",
                fg="#8da2af",
                font=(
                    "Arial",
                    10
                )
            ).pack(
                side="left"
            )

            tk.Label(
                row,
                textvariable=
                    variable,
                bg="#101f29",
                fg="#ffffff",
                font=(
                    "Arial",
                    10,
                    "bold"
                )
            ).pack(
                side="right"
            )

        scan_button = tk.Button(
            self.body,
            text=
                "Scan Entire Network Now",
            bg="#35e79a",
            fg="#042116",
            activebackground=
                "#35e79a",
            relief="flat",
            font=(
                "Arial",
                11,
                "bold"
            ),
            command=
                self.manual_scan
        )

        scan_button.pack(
            fill="x",
            ipady=9,
            pady=(20, 10)
        )

        self.label(
            self.body,
            (
                "Automatic monitoring is enabled. "
                f"The network is rescanned approximately "
                f"every {SCAN_INTERVAL} seconds."
            ),
            9,
            False,
            "#8da2af"
        ).pack(
            pady=(4, 9)
        )

        self.label(
            self.body,
            (
                "Security checks are limited, "
                "non-invasive local service checks. "
                "They do not prove that a device "
                "is fully secure."
            ),
            9,
            False,
            "#8da2af"
        ).pack(
            pady=(0, 10)
        )

        self.label(
            self.body,
            (
                "Diagnostic log:\n"
                f"{LOG_FILE}"
            ),
            8,
            False,
            "#617986"
        ).pack(
            pady=(0, 16)
        )

        disconnect = tk.Button(
            self.body,
            text=
                "Disconnect this Agent",
            bg="#13232d",
            fg="#ff8a8a",
            activebackground=
                "#13232d",
            relief="flat",
            command=
                self.disconnect
        )

        disconnect.pack(
            fill="x",
            ipady=7
        )

    # ========================================================
    # MONITORING
    # ========================================================

    def start_monitoring(self):

        if (
            self.monitor_thread
            and
            self.monitor_thread
            .is_alive()
        ):

            return

        self.stop_event.clear()

        self.monitor_thread = (
            threading.Thread(
                target=
                    self.monitor_loop,
                daemon=True
            )
        )

        self.monitor_thread.start()

    def monitor_loop(self):

        while not (
            self.stop_event
            .is_set()
        ):

            self.perform_scan()

            self.stop_event.wait(
                SCAN_INTERVAL
            )

    def manual_scan(self):

        threading.Thread(
            target=
                self.perform_scan,
            daemon=True
        ).start()

    def perform_scan(self):

        if not self.is_paired():
            return

        if not self.scan_lock.acquire(
            blocking=False
        ):

            return

        try:

            self.root.after(
                0,
                lambda:
                    self.status_value.set(
                        "Scanning..."
                    )
            )

            heartbeat(
                self.config
            )

            (
                devices,
                network,
                local_ip
            ) = scan_network()

            result = sync_devices(
                self.config,
                devices
            )

            if isinstance(
                result,
                dict
            ):

                count = result.get(
                    "devices_seen",
                    len(devices)
                )

            else:

                count = len(
                    devices
                )

            warning_count = sum(
                1
                for device in devices
                if device.get(
                    "security_status"
                ) == "warning"
            )

            review_count = sum(
                1
                for device in devices
                if device.get(
                    "security_status"
                ) == "review"
            )

            self.root.after(
                0,
                lambda:
                    self.update_scan_success(
                        count,
                        str(network),
                        local_ip,
                        warning_count,
                        review_count
                    )
            )

        except Exception as exc:

            log(
                f"SCAN ERROR: {exc}"
            )

            self.root.after(
                0,
                lambda:
                    self.update_scan_error(
                        str(exc)
                    )
            )

        finally:

            self.scan_lock.release()

    def update_scan_success(
        self,
        count,
        network,
        local_ip,
        warning_count,
        review_count
    ):

        self.status_value.set(
            "Online"
        )

        self.network_value.set(
            f"{network} "
            f"({local_ip})"
        )

        self.device_value.set(
            str(count)
        )

        if warning_count:

            self.security_value.set(
                f"{warning_count} warning(s), "
                f"{review_count} review"
            )

        elif review_count:

            self.security_value.set(
                f"{review_count} item(s) to review"
            )

        else:

            self.security_value.set(
                "No obvious issues found"
            )

        self.scan_value.set(
            time.strftime(
                "%H:%M:%S"
            )
        )

    def update_scan_error(
        self,
        error
    ):

        self.status_value.set(
            "Error"
        )

        self.security_value.set(
            "Scan failed"
        )

        log(
            f"UI scan error: {error}"
        )

    # ========================================================
    # DISCONNECT
    # ========================================================

    def disconnect(self):

        confirmed = (
            messagebox.askyesno(
                "Disconnect Agent",
                (
                    "Disconnect this computer "
                    "from WiFi Watch?"
                )
            )
        )

        if not confirmed:
            return

        self.stop_event.set()

        delete_config()

        self.config = {}

        self.show_pairing()

    # ========================================================
    # CLOSE
    # ========================================================

    def close(self):

        self.stop_event.set()

        self.root.destroy()

    def run(self):

        self.root.mainloop()


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    if (
        "YOUR_REAL_"
        in SUPABASE_URL
        or
        "YOUR_REAL_"
        in SUPABASE_KEY
    ):

        root = tk.Tk()

        root.withdraw()

        messagebox.showerror(
            "WiFi Watch",
            (
                "Supabase URL and publishable key "
                "have not been configured."
            )
        )

        root.destroy()

        raise SystemExit(1)

    log(
        f"Starting WiFi Watch Agent "
        f"{APP_VERSION} on "
        f"{platform.system()}"
    )

    app = WiFiWatchApp()

    app.run()
