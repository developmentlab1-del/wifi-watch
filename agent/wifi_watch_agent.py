import concurrent.futures
import errno
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET

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
# OPTIONAL OFFLINE MAC MANUFACTURER DATABASE
# ============================================================

try:

    from manuf import manuf

    MAC_VENDOR_PARSER = (
        manuf.MacParser()
    )

except Exception:

    MAC_VENDOR_PARSER = None


# ============================================================
# WIFI WATCH
# ============================================================

APP_VERSION = "0.3.0"


# ============================================================
# IMPORTANT
#
# KEEP YOUR REAL VALUES HERE.
#
# ONLY:
#   sb_publishable_...
#
# NEVER:
#   sb_secret_
#   service_role
#   database password
# ============================================================

SUPABASE_URL = "https://ephdcwogebxfsidytmrj.supabase.co"

SUPABASE_KEY = "sb_publishable_L9TUAFyJ_S0l81UDNi8imw_FVTYm4cI"


SCAN_INTERVAL = 30

REQUEST_TIMEOUT = 20

MAX_WORKERS = 80

MAX_NETWORK_ADDRESSES = 1024


# ============================================================
# TCP SERVICES
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

    8001: "HTTP-alt",

    8008: "Google Cast",

    8009: "Google Cast",

    8080: "HTTP-alt",

    8443: "HTTPS-alt",

    8883: "MQTT-TLS",

    9100: "RAW Printer",

    32400: "Plex",

    62078: "Apple Sync",

}


REFUSED_CODES = {

    errno.ECONNREFUSED,

    61,

    111,

    10061,

}


# ============================================================
# MDNS SERVICES
# ============================================================

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

    "_spotify-connect._tcp.local.",

}


# ============================================================
# APP STORAGE
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
            /
            "WiFiWatch"
        )


    elif system == "Darwin":

        folder = (

            Path.home()
            /
            "Library"
            /
            "Application Support"
            /
            "WiFiWatch"

        )


    else:

        folder = (

            Path.home()
            /
            ".config"
            /
            "WiFiWatch"

        )


    folder.mkdir(

        parents=True,

        exist_ok=True

    )


    return folder


APP_FOLDER = get_app_folder()

CONFIG_FILE = (
    APP_FOLDER
    /
    "agent.json"
)

LOG_FILE = (
    APP_FOLDER
    /
    "agent.log"
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
# SUPABASE
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


    response = requests.post(

        url,

        headers={

            "apikey":
                SUPABASE_KEY,

            "Content-Type":
                "application/json",

        },

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

        "network_id",

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


    return config


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
# MAC HELPERS
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


    result = []


    try:

        for part in parts:

            if (
                not part
                or
                len(part) > 2
            ):

                return None


            result.append(

                f"{int(part, 16):02x}"

            )


    except Exception:

        return None


    return ":".join(
        result
    )


def valid_mac(mac):

    mac = normalize_mac(
        mac
    )


    if not mac:

        return False


    if mac in (

        "00:00:00:00:00:00",

        "ff:ff:ff:ff:ff:ff",

    ):

        return False


    try:

        first = int(

            mac.split(":")[0],

            16

        )


        if first & 1:

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

        first = int(

            mac.split(":")[0],

            16

        )


        return bool(
            first & 2
        )


    except Exception:

        return False


def lookup_mac_vendor(mac):

    mac = normalize_mac(
        mac
    )


    if not valid_mac(mac):

        return None


    if is_private_mac(mac):

        return None


    if not MAC_VENDOR_PARSER:

        return None


    try:

        comment = (
            MAC_VENDOR_PARSER
            .get_comment(mac)
        )


        manufacturer = (
            MAC_VENDOR_PARSER
            .get_manuf(mac)
        )


        return (
            comment
            or
            manufacturer
            or
            None
        )


    except Exception:

        return None


# ============================================================
# NAME HELPERS
# ============================================================

def decode_dns_name(value):

    if not value:

        return None


    value = str(
        value
    )


    def replace_oct(match):

        try:

            return chr(

                int(
                    match.group(1),
                    8
                )

            )

        except Exception:

            return match.group(0)


    value = re.sub(

        r"\\([0-7]{3})",

        replace_oct,

        value

    )


    return value


def clean_device_name(value):

    if not value:

        return None


    value = decode_dns_name(
        value
    )


    value = (
        str(value)
        .strip()
        .strip(".")
    )


    if "._" in value:

        value = value.split(
            "._",
            1
        )[0]


    if value.lower().endswith(
        ".local"
    ):

        value = value[:-6]


    value = value.strip()


    if not value:

        return None


    if len(value) > 120:

        return None


    try:

        ipaddress.ip_address(
            value
        )

        return None

    except Exception:

        pass


    return value


# ============================================================
# DEVICE RECORD
# ============================================================

def create_record(ip):

    return {

        "ip":
            str(ip),

        "mac":
            None,

        "methods":
            set(),

        "open_ports":
            set(),

        "identity_sources":
            set(),

        "friendly_candidates":
            [],

        "hostname_candidates":
            [],

        "vendor_candidates":
            [],

        "model_candidates":
            [],

        "mdns":
            [],

        "ssdp":
            [],

        "nbns":
            [],

        "reverse_dns":
            None,

        "gateway":
            False,

    }


def ensure_record(
    records,
    network,
    ip
):

    try:

        address = ipaddress.ip_address(
            str(ip)
        )

    except Exception:

        return None


    if (
        address.version != 4
        or
        address not in network
    ):

        return None


    key = str(
        address
    )


    if key not in records:

        records[key] = (
            create_record(
                key
            )
        )


    return records[key]


def add_candidate(
    record,
    field,
    value,
    source,
    score
):

    value = clean_device_name(
        value
    )


    if not value:

        return


    record[field].append({

        "value":
            value,

        "source":
            source,

        "score":
            score,

    })


    record[
        "identity_sources"
    ].add(
        source
    )


def add_raw_candidate(
    record,
    field,
    value,
    source,
    score
):

    if not value:

        return


    value = str(
        value
    ).strip()


    if not value:

        return


    record[field].append({

        "value":
            value,

        "source":
            source,

        "score":
            score,

    })


    record[
        "identity_sources"
    ].add(
        source
    )


def best_candidate(
    record,
    field
):

    candidates = record.get(
        field,
        []
    )


    if not candidates:

        return None


    candidates = sorted(

        candidates,

        key=lambda item:
            item.get(
                "score",
                0
            ),

        reverse=True

    )


    return candidates[0][
        "value"
    ]


# ============================================================
# LOCAL NETWORK
# ============================================================

def get_primary_local_ip():

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


        ip = sock.getsockname()[0]


        if ip:

            return ip


    except Exception:

        pass


    finally:

        sock.close()


    for addresses in (

        psutil
        .net_if_addrs()
        .values()

    ):

        for address in addresses:

            if (
                address.family
                ==
                socket.AF_INET
            ):

                try:

                    ip = ipaddress.ip_address(
                        address.address
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
        "Unable to determine local IPv4 address."
    )


def get_network_details():

    local_ip = (
        get_primary_local_ip()
    )


    interface_name = None

    netmask = None

    own_mac = None


    for (
        name,
        addresses
    ) in (

        psutil
        .net_if_addrs()
        .items()

    ):

        matched = False


        for address in addresses:

            if (

                address.family
                ==
                socket.AF_INET

                and

                address.address
                ==
                local_ip

            ):

                interface_name = name

                netmask = address.netmask

                matched = True

                break


        if not matched:

            continue


        for address in addresses:

            if (
                address.family
                ==
                psutil.AF_LINK
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
        >
        MAX_NETWORK_ADDRESSES
    ):

        network = ipaddress.ip_network(

            f"{local_ip}/24",

            strict=False

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
# DEFAULT GATEWAY
# ============================================================

def get_default_gateway():

    system = platform.system()


    try:

        if system == "Darwin":

            route = get_command(

                "route",

                [
                    "/sbin/route",
                    "/usr/sbin/route"
                ]

            )


            output = subprocess.check_output(

                [
                    route,
                    "-n",
                    "get",
                    "default"
                ],

                text=True,

                stderr=subprocess.DEVNULL

            )


            match = re.search(

                r"gateway:\s*"
                r"(\d+\.\d+\.\d+\.\d+)",

                output

            )


            if match:

                return match.group(1)


        elif system == "Linux":

            ip_command = get_command(

                "ip",

                [
                    "/usr/sbin/ip",
                    "/usr/bin/ip",
                    "/sbin/ip"
                ]

            )


            output = subprocess.check_output(

                [
                    ip_command,
                    "route",
                    "show",
                    "default"
                ],

                text=True,

                stderr=subprocess.DEVNULL

            )


            match = re.search(

                r"default\s+via\s+"
                r"(\d+\.\d+\.\d+\.\d+)",

                output

            )


            if match:

                return match.group(1)


        elif system == "Windows":

            output = subprocess.check_output(

                [
                    "route",
                    "print",
                    "-4"
                ],

                text=True,

                errors="ignore",

                stderr=subprocess.DEVNULL

            )


            match = re.search(

                r"^\s*0\.0\.0\.0"
                r"\s+0\.0\.0\.0"
                r"\s+(\d+\.\d+\.\d+\.\d+)",

                output,

                re.MULTILINE

            )


            if match:

                return match.group(1)


    except Exception:

        pass


    return None


# ============================================================
# NEIGHBOR SEED
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
# PING
# ============================================================

def ping_host(ip):

    ip = str(ip)

    system = platform.system()

    flags = 0


    if system == "Darwin":

        command = [

            get_command(
                "ping",
                [
                    "/sbin/ping",
                    "/usr/bin/ping"
                ]
            ),

            "-c",
            "1",

            "-W",
            "700",

            ip,

        ]


    elif system == "Windows":

        command = [

            "ping",

            "-n",
            "1",

            "-w",
            "700",

            ip,

        ]


        if hasattr(
            subprocess,
            "CREATE_NO_WINDOW"
        ):

            flags = (
                subprocess.CREATE_NO_WINDOW
            )


    else:

        command = [

            get_command(
                "ping",
                [
                    "/usr/bin/ping",
                    "/bin/ping"
                ]
            ),

            "-c",
            "1",

            "-W",
            "1",

            ip,

        ]


    try:

        result = subprocess.run(

            command,

            stdout=subprocess.DEVNULL,

            stderr=subprocess.DEVNULL,

            timeout=2,

            creationflags=flags

        )


        if result.returncode == 0:

            return ip


    except Exception:

        pass


    return None


# ============================================================
# TCP SERVICES
# ============================================================

def tcp_probe(ip):

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
# ARP / NEIGHBOR TABLE
# ============================================================

def get_macos_neighbors():

    command = get_command(

        "arp",

        [
            "/usr/sbin/arp",
            "/sbin/arp"
        ]

    )


    output = subprocess.check_output(

        [
            command,
            "-an"
        ],

        text=True,

        stderr=subprocess.DEVNULL

    )


    result = {}


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


        if valid_mac(mac):

            result[ip] = mac


    return result


def get_windows_neighbors():

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
            "arp",
            "-a"
        ],

        text=True,

        errors="ignore",

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


        if valid_mac(mac):

            result[ip] = mac


    return result


def get_linux_neighbors():

    result = {}


    command = get_command(

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
                command,
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


            if valid_mac(mac):

                result[ip] = mac


    except Exception:

        pass


    return result


def get_neighbor_table():

    try:

        if platform.system() == "Darwin":

            return get_macos_neighbors()


        if platform.system() == "Windows":

            return get_windows_neighbors()


        return get_linux_neighbors()


    except Exception as exc:

        log(
            f"Neighbor table error: {exc}"
        )


        return {}


# ============================================================
# REVERSE DNS
# ============================================================

def reverse_dns(ip):

    try:

        name = (
            socket.gethostbyaddr(
                ip
            )[0]
        )


        return (
            ip,
            name
        )


    except Exception:

        return (
            ip,
            None
        )


# ============================================================
# NETBIOS NAME DISCOVERY
# ============================================================

def netbios_encode_name():

    raw = (
        b"*"
        +
        b"\x00" * 15
    )


    encoded = bytearray()


    for byte in raw:

        encoded.append(

            ord("A")
            +
            ((byte >> 4) & 0x0F)

        )

        encoded.append(

            ord("A")
            +
            (byte & 0x0F)

        )


    return (

        b"\x20"
        +
        bytes(encoded)
        +
        b"\x00"

    )


def netbios_names(ip):

    transaction_id = (
        int(time.time() * 1000)
        &
        0xFFFF
    )


    header = struct.pack(

        "!HHHHHH",

        transaction_id,

        0x0000,

        1,

        0,

        0,

        0

    )


    question = (

        netbios_encode_name()

        +

        struct.pack(
            "!HH",
            0x0021,
            0x0001
        )

    )


    packet = (
        header
        +
        question
    )


    sock = socket.socket(

        socket.AF_INET,

        socket.SOCK_DGRAM

    )


    sock.settimeout(
        0.6
    )


    try:

        sock.sendto(

            packet,

            (
                ip,
                137
            )

        )


        data, _address = (
            sock.recvfrom(
                4096
            )
        )


    except Exception:

        return []


    finally:

        sock.close()


    try:

        if len(data) < 60:

            return []


        offset = 12


        while (
            offset < len(data)
        ):

            length = data[offset]

            offset += 1


            if length == 0:

                break


            offset += length


        offset += 4


        if (
            data[offset]
            &
            0xC0
        ) == 0xC0:

            offset += 2


        else:

            while True:

                length = data[offset]

                offset += 1


                if length == 0:

                    break


                offset += length


        _type, _class, _ttl, rdlength = (
            struct.unpack(

                "!HHIH",

                data[
                    offset:
                    offset + 10
                ]

            )
        )


        offset += 10


        rdata = data[
            offset:
            offset + rdlength
        ]


        if not rdata:

            return []


        count = rdata[0]

        position = 1

        names = []


        for _ in range(
            count
        ):

            entry = rdata[
                position:
                position + 18
            ]


            if len(entry) < 18:

                break


            raw_name = (

                entry[:15]

                .decode(
                    "ascii",
                    errors="ignore"
                )

                .rstrip(
                    " \x00"
                )

            )


            suffix = entry[15]


            flags = struct.unpack(

                "!H",

                entry[16:18]

            )[0]


            group_name = bool(
                flags & 0x8000
            )


            if (

                raw_name

                and

                raw_name != "*"

                and

                not group_name

                and

                suffix in (
                    0x00,
                    0x20
                )

            ):

                if raw_name not in names:

                    names.append(
                        raw_name
                    )


            position += 18


        return names


    except Exception:

        return []


# ============================================================
# SSDP / UPNP
# ============================================================

def parse_ssdp_headers(
    data
):

    try:

        text = data.decode(
            "utf-8",
            errors="ignore"
        )


    except Exception:

        return {}


    headers = {}


    for line in text.splitlines()[1:]:

        if ":" not in line:

            continue


        key, value = line.split(
            ":",
            1
        )


        headers[
            key.strip().lower()
        ] = (
            value.strip()
        )


    return headers


def discover_ssdp():

    results = []


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
            0.35
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
            time.time()
            +
            3
        )


        while (
            time.time()
            <
            deadline
        ):

            try:

                data, address = (
                    sock.recvfrom(
                        65535
                    )
                )


                results.append({

                    "ip":
                        address[0],

                    "headers":
                        parse_ssdp_headers(
                            data
                        ),

                })


            except socket.timeout:

                continue


            except Exception:

                break


    finally:

        sock.close()


    return results


def local_location_allowed(
    location,
    network
):

    try:

        parsed = urllib.parse.urlparse(
            location
        )


        if parsed.scheme not in (
            "http",
            "https"
        ):

            return False


        hostname = parsed.hostname


        if not hostname:

            return False


        try:

            address = ipaddress.ip_address(
                hostname
            )


        except Exception:

            resolved = socket.gethostbyname(
                hostname
            )


            address = ipaddress.ip_address(
                resolved
            )


        return (
            address.version == 4
            and
            address in network
        )


    except Exception:

        return False


def xml_text(
    root,
    tag_name
):

    tag_name = tag_name.lower()


    for element in root.iter():

        local_name = (

            element.tag
            .split("}")[-1]
            .lower()

        )


        if (
            local_name
            ==
            tag_name
        ):

            if element.text:

                value = (
                    element.text.strip()
                )


                if value:

                    return value


    return None


def fetch_upnp_identity(
    location,
    network
):

    if not local_location_allowed(
        location,
        network
    ):

        return None


    try:

        response = requests.get(

            location,

            timeout=(
                0.8,
                1.5
            ),

            allow_redirects=False,

            verify=False,

            headers={
                "User-Agent":
                    f"WiFiWatch/{APP_VERSION}"
            }

        )


        if not response.ok:

            return None


        content = (
            response.content[
                :524288
            ]
        )


        root = ET.fromstring(
            content
        )


        model_name = xml_text(
            root,
            "modelName"
        )


        model_number = xml_text(
            root,
            "modelNumber"
        )


        model = None


        if (
            model_name
            and
            model_number
            and
            model_number.lower()
            not in model_name.lower()
        ):

            model = (
                f"{model_name} "
                f"{model_number}"
            )


        else:

            model = (
                model_name
                or
                model_number
            )


        return {

            "friendly_name":
                xml_text(
                    root,
                    "friendlyName"
                ),

            "manufacturer":
                xml_text(
                    root,
                    "manufacturer"
                ),

            "model":
                model,

            "device_type":
                xml_text(
                    root,
                    "deviceType"
                ),

        }


    except Exception:

        return None


# ============================================================
# MDNS
# ============================================================

def decode_txt_properties(
    properties
):

    decoded = {}


    for (
        raw_key,
        raw_value
    ) in properties.items():

        try:

            key = (

                raw_key.decode(
                    errors="ignore"
                )

                if isinstance(
                    raw_key,
                    bytes
                )

                else str(
                    raw_key
                )

            )


            value = (

                raw_value.decode(
                    errors="ignore"
                )

                if isinstance(
                    raw_value,
                    bytes
                )

                else str(
                    raw_value
                )

            )


            decoded[
                key.lower()
            ] = value


        except Exception:

            pass


    return decoded


class MDNSListener(
    ServiceListener
):

    def __init__(
        self,
        results
    ):

        self.results = results

        self.lock = (
            threading.Lock()
        )


    def add_service(
        self,
        zeroconf,
        service_type,
        name
    ):

        self.read_service(

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

        self.read_service(

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


    def read_service(
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

                    timeout=750

                )
            )


            if not info:

                return


            properties = (
                decode_txt_properties(
                    info.properties
                )
            )


            instance = (
                clean_device_name(
                    name
                )
            )


            server = (
                clean_device_name(
                    info.server
                )
            )


            for ip in (
                info.parsed_addresses(
                    IPVersion.V4Only
                )
            ):

                record = {

                    "service_type":
                        service_type,

                    "instance":
                        instance,

                    "server":
                        server,

                    "port":
                        info.port,

                    "properties":
                        properties,

                }


                with self.lock:

                    self.results.setdefault(
                        ip,
                        []
                    ).append(
                        record
                    )


        except Exception:

            pass


def discover_mdns():

    results = {}

    zeroconf = None

    browsers = []


    try:

        zeroconf = Zeroconf(

            ip_version=
                IPVersion.V4Only

        )


        listener = (
            MDNSListener(
                results
            )
        )


        for service_type in (
            DEFAULT_MDNS_TYPES
        ):

            try:

                browser = ServiceBrowser(

                    zeroconf,

                    service_type,

                    listener

                )


                browsers.append(
                    browser
                )


            except Exception:

                pass


        time.sleep(
            4
        )


    except Exception as exc:

        log(
            f"mDNS error: {exc}"
        )


    finally:

        for browser in browsers:

            try:

                browser.cancel()

            except Exception:

                pass


        if zeroconf:

            try:

                zeroconf.close()

            except Exception:

                pass


    return results


# ============================================================
# IDENTITY PROCESSING
# ============================================================

def apply_mdns_identity(
    record,
    entries
):

    record["mdns"] = (
        entries[:20]
    )


    for entry in entries:

        service = (
            entry.get(
                "service_type",
                ""
            )
        )


        instance = (
            entry.get(
                "instance"
            )
        )


        server = (
            entry.get(
                "server"
            )
        )


        properties = (
            entry.get(
                "properties",
                {}
            )
        )


        if instance:

            score = 76


            if any(

                token in service

                for token in (
                    "_googlecast",
                    "_airplay",
                    "_raop",
                    "_ipp",
                    "_printer"
                )

            ):

                score = 84


            add_candidate(

                record,

                "friendly_candidates",

                instance,

                "mdns",

                score

            )


        if server:

            add_candidate(

                record,

                "hostname_candidates",

                server,

                "mdns",

                68

            )


        friendly_keys = (

            "fn",

            "friendlyname",

            "friendly_name",

            "name",

            "n",

        )


        for key in friendly_keys:

            if properties.get(
                key
            ):

                add_candidate(

                    record,

                    "friendly_candidates",

                    properties[key],

                    "mdns_txt",

                    91

                )


        model_keys = (

            "md",

            "model",

            "am",

        )


        for key in model_keys:

            value = properties.get(
                key
            )


            if value:

                add_raw_candidate(

                    record,

                    "model_candidates",

                    value,

                    "mdns_txt",

                    86

                )


        vendor_keys = (

            "manufacturer",

            "vendor",

            "mf",

        )


        for key in vendor_keys:

            value = properties.get(
                key
            )


            if value:

                add_raw_candidate(

                    record,

                    "vendor_candidates",

                    value,

                    "mdns_txt",

                    85

                )


        record[
            "identity_sources"
        ].add(
            "mdns"
        )


def apply_ssdp_identity(
    record,
    ssdp_records,
    network
):

    saved = []


    processed_locations = set()


    for item in ssdp_records:

        headers = item.get(
            "headers",
            {}
        )


        location = headers.get(
            "location"
        )


        saved.append({

            "server":
                headers.get(
                    "server"
                ),

            "st":
                headers.get(
                    "st"
                ),

            "usn":
                headers.get(
                    "usn"
                ),

            "location":
                location,

        })


        if (
            not location
            or
            location in processed_locations
        ):

            continue


        processed_locations.add(
            location
        )


        identity = (
            fetch_upnp_identity(
                location,
                network
            )
        )


        if not identity:

            continue


        friendly = identity.get(
            "friendly_name"
        )


        manufacturer = identity.get(
            "manufacturer"
        )


        model = identity.get(
            "model"
        )


        if friendly:

            add_candidate(

                record,

                "friendly_candidates",

                friendly,

                "ssdp_upnp",

                95

            )


        if manufacturer:

            add_raw_candidate(

                record,

                "vendor_candidates",

                manufacturer,

                "ssdp_upnp",

                96

            )


        if model:

            add_raw_candidate(

                record,

                "model_candidates",

                model,

                "ssdp_upnp",

                96

            )


        saved[-1][
            "upnp_identity"
        ] = identity


        record[
            "identity_sources"
        ].add(
            "ssdp_upnp"
        )


    record["ssdp"] = (
        saved[:15]
    )


def apply_reverse_dns(
    record,
    hostname
):

    if not hostname:

        return


    record[
        "reverse_dns"
    ] = hostname


    add_candidate(

        record,

        "hostname_candidates",

        hostname,

        "reverse_dns",

        65

    )


def apply_nbns(
    record,
    names
):

    record["nbns"] = (
        names[:10]
    )


    if not names:

        return


    add_candidate(

        record,

        "friendly_candidates",

        names[0],

        "netbios",

        86

    )


    add_candidate(

        record,

        "hostname_candidates",

        names[0],

        "netbios",

        84

    )


# ============================================================
# DEVICE TYPE
# ============================================================

def infer_device_type(
    record,
    friendly,
    hostname,
    vendor,
    model
):

    if record.get(
        "gateway"
    ):

        return "router_gateway"


    combined = " ".join(

        value

        for value in (

            friendly,
            hostname,
            vendor,
            model

        )

        if value

    ).lower()


    mdns_services = " ".join(

        item.get(
            "service_type",
            ""
        )

        for item in record.get(
            "mdns",
            []
        )

    ).lower()


    ssdp_text = json.dumps(

        record.get(
            "ssdp",
            []
        )

    ).lower()


    ports = record.get(
        "open_ports",
        set()
    )


    if (
        "_ipp." in mdns_services

        or

        "_printer." in mdns_services

        or

        631 in ports

        or

        9100 in ports

        or

        "printer" in combined

        or

        "laserjet" in combined
    ):

        return "printer"


    if any(

        word in combined

        for word in (

            "iphone",

            "ipad",

            "android",

            "galaxy",

            "pixel",

            "phone",

        )

    ):

        return "mobile"


    if any(

        word in combined

        for word in (

            "playstation",

            "ps5",

            "ps4",

            "xbox",

            "nintendo",

            "switch",

        )

    ):

        return "game_console"


    if (

        "_googlecast."
        in mdns_services

        or

        "_airplay."
        in mdns_services

        or

        "mediarenderer"
        in ssdp_text

        or

        any(

            word in combined

            for word in (

                "apple tv",

                "appletv",

                "chromecast",

                "google tv",

                "roku",

                "smart tv",

                "television",

                "bravia",

                "webos",

                "tizen",

            )

        )

    ):

        return "smart_tv_media"


    if any(

        word in combined

        for word in (

            "camera",

            "cam ",

            "ipcam",

            "doorbell",

            "reolink",

            "hikvision",

            "dahua",

            "ring",

        )

    ):

        return "camera"


    if (

        "_hap."
        in mdns_services

        or

        any(

            word in combined

            for word in (

                "homepod",

                "homekit",

                "smart plug",

                "smart bulb",

                "hue",

                "thermostat",

                "nest",

            )

        )

    ):

        return "smart_home"


    if (

        "mediaserver"
        in ssdp_text

        or

        32400 in ports

    ):

        return "media_server"


    if any(

        word in combined

        for word in (

            "synology",

            "qnap",

            "nas",

        )

    ):

        return "nas"


    if (

        445 in ports

        or

        139 in ports

        or

        3389 in ports

        or

        "_smb."
        in mdns_services

    ):

        return "computer_or_nas"


    if (

        22 in ports

        or

        "_ssh."
        in mdns_services

    ):

        return "computer_or_server"


    if 62078 in ports:

        return "apple_device"


    return "unknown"


# ============================================================
# OS GUESS
# ============================================================

def infer_os(
    record,
    friendly,
    hostname,
    model,
    device_type
):

    combined = " ".join(

        value

        for value in (

            friendly,
            hostname,
            model

        )

        if value

    ).lower()


    ports = record.get(
        "open_ports",
        set()
    )


    if (
        "iphone" in combined
        or
        "ipad" in combined
    ):

        return "Apple iOS/iPadOS"


    if (
        "android" in combined
        or
        "galaxy" in combined
        or
        "pixel" in combined
    ):

        return "Android"


    if (
        "apple tv" in combined
        or
        "appletv" in combined
    ):

        return "Apple tvOS"


    if (
        "windows" in combined
        or
        3389 in ports
    ):

        return "Windows-like"


    if (
        device_type
        ==
        "apple_device"
    ):

        return "Apple OS"


    return None


# ============================================================
# SECURITY
# ============================================================

def build_security_assessment(
    ports
):

    ports = set(
        ports
    )


    findings = []


    if 23 in ports:

        findings.append({

            "severity":
                "warning",

            "title":
                "Telnet service reachable",

            "detail":
                (
                    "Telnet is an unencrypted "
                    "remote-access protocol."
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
                    "FTP may transmit credentials "
                    "and data without encryption."
                ),

            "port":
                21,

        })


    review_ports = {

        80:
            (
                "HTTP service reachable",
                "An unencrypted HTTP service is reachable."
            ),

        445:
            (
                "SMB service reachable",
                "File sharing is reachable from the local network."
            ),

        3389:
            (
                "Remote Desktop reachable",
                "RDP is reachable from the local network."
            ),

        1883:
            (
                "MQTT service reachable",
                "MQTT is available on its common non-TLS port."
            ),

        554:
            (
                "RTSP service reachable",
                "A media streaming service is reachable."
            ),

        9100:
            (
                "Raw printer service reachable",
                "Raw TCP printing is reachable."
            ),

    }


    for (
        port,
        information
    ) in review_ports.items():

        if port in ports:

            findings.append({

                "severity":
                    "review",

                "title":
                    information[0],

                "detail":
                    information[1],

                "port":
                    port,

            })


    severities = {

        item["severity"]

        for item in findings

    }


    if "warning" in severities:

        return (
            "warning",
            findings
        )


    if "review" in severities:

        return (
            "review",
            findings
        )


    if ports:

        return (

            "no_obvious_issues",

            [{

                "severity":
                    "info",

                "title":
                    "No obvious risky service detected",

                "detail":
                    (
                        "The limited local service scan "
                        "did not identify one of the "
                        "currently flagged services. "
                        "This does not prove that the "
                        "device is fully secure."
                    ),

            }]

        )


    return (

        "unknown",

        [{

            "severity":
                "info",

            "title":
                "Security status not determined",

            "detail":
                (
                    "The device was discovered but none "
                    "of the limited TCP services checked "
                    "by WiFi Watch responded."
                ),

        }]

    )


# ============================================================
# IDENTITY CONFIDENCE
# ============================================================

def calculate_confidence(
    record,
    friendly,
    hostname,
    vendor,
    model
):

    scores = []


    for field in (

        "friendly_candidates",

        "hostname_candidates",

        "vendor_candidates",

        "model_candidates",

    ):

        for candidate in record.get(
            field,
            []
        ):

            scores.append(

                candidate.get(
                    "score",
                    0
                )

            )


    if record.get(
        "gateway"
    ):

        scores.append(
            90
        )


    if not scores:

        base = 15

    else:

        base = max(
            scores
        )


    if (
        vendor
        and
        model
    ):

        base += 4


    if (
        friendly
        and
        hostname
    ):

        base += 2


    if record.get(
        "mac"
    ):

        base += 2


    if (
        len(
            record.get(
                "identity_sources",
                set()
            )
        )
        >=
        3
    ):

        base += 2


    return max(

        0,

        min(
            99,
            base
        )

    )


# ============================================================
# BUILD SERVICES
# ============================================================

def build_services(
    ports
):

    return [

        {

            "protocol":
                "tcp",

            "port":
                port,

            "name":
                TCP_SERVICES.get(
                    port,
                    "Unknown"
                ),

            "source":
                "tcp_connect",

        }

        for port in sorted(
            ports
        )

    ]


# ============================================================
# MAIN SCAN
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


    records = {}


    local_record = (
        ensure_record(
            records,
            network,
            local_ip
        )
    )


    local_record[
        "methods"
    ].add(
        "agent"
    )


    local_record["mac"] = (
        own_mac
    )


    add_candidate(

        local_record,

        "friendly_candidates",

        socket.gethostname(),

        "local_agent",

        99

    )


    add_candidate(

        local_record,

        "hostname_candidates",

        socket.gethostname(),

        "local_agent",

        99

    )


    gateway = (
        get_default_gateway()
    )


    if gateway:

        gateway_record = (
            ensure_record(
                records,
                network,
                gateway
            )
        )


        if gateway_record:

            gateway_record[
                "gateway"
            ] = True


            gateway_record[
                "methods"
            ].add(
                "gateway"
            )


            add_candidate(

                gateway_record,

                "friendly_candidates",

                "Network Gateway",

                "gateway",

                90

            )


    log(
        "=============================================="
    )


    log(
        f"WiFi Watch Expert Scan v{APP_VERSION}"
    )


    log(
        f"Network: {network}"
    )


    log(
        f"Agent IP: {local_ip}"
    )


    log(
        f"Gateway: {gateway}"
    )


    # ========================================================
    # PASS 1 - NEIGHBOR RESOLUTION
    # ========================================================

    with concurrent.futures.ThreadPoolExecutor(

        max_workers=
            MAX_WORKERS

    ) as executor:

        list(
            executor.map(
                seed_neighbor,
                hosts
            )
        )


    # ========================================================
    # PASS 2 - PING
    # ========================================================

    with concurrent.futures.ThreadPoolExecutor(

        max_workers=
            MAX_WORKERS

    ) as executor:

        futures = [

            executor.submit(
                ping_host,
                ip
            )

            for ip in hosts

        ]


        for future in concurrent.futures.as_completed(
            futures
        ):

            try:

                ip = future.result()


                if not ip:

                    continue


                record = ensure_record(

                    records,

                    network,

                    ip

                )


                if record:

                    record[
                        "methods"
                    ].add(
                        "icmp"
                    )


            except Exception:

                pass


    # ========================================================
    # PASS 3 - TCP
    # ========================================================

    with concurrent.futures.ThreadPoolExecutor(

        max_workers=
            MAX_WORKERS

    ) as executor:

        futures = [

            executor.submit(
                tcp_probe,
                ip
            )

            for ip in hosts

        ]


        for future in concurrent.futures.as_completed(
            futures
        ):

            try:

                (
                    ip,
                    alive,
                    open_ports
                ) = future.result()


                if not alive:

                    continue


                record = ensure_record(

                    records,

                    network,

                    ip

                )


                if not record:

                    continue


                record[
                    "methods"
                ].add(
                    "tcp"
                )


                record[
                    "open_ports"
                ].update(
                    open_ports
                )


            except Exception:

                pass


    # ========================================================
    # PASS 4 - SSDP
    # ========================================================

    ssdp_by_ip = {}


    for item in discover_ssdp():

        ip = item.get(
            "ip"
        )


        record = ensure_record(

            records,

            network,

            ip

        )


        if not record:

            continue


        record[
            "methods"
        ].add(
            "ssdp"
        )


        ssdp_by_ip.setdefault(

            ip,

            []

        ).append(
            item
        )


    for (
        ip,
        entries
    ) in ssdp_by_ip.items():

        apply_ssdp_identity(

            records[ip],

            entries,

            network

        )


    # ========================================================
    # PASS 5 - MDNS
    # ========================================================

    mdns_results = (
        discover_mdns()
    )


    for (
        ip,
        entries
    ) in mdns_results.items():

        record = ensure_record(

            records,

            network,

            ip

        )


        if not record:

            continue


        record[
            "methods"
        ].add(
            "mdns"
        )


        apply_mdns_identity(

            record,

            entries

        )


    # ========================================================
    # PASS 6 - ARP TABLE
    # ========================================================

    time.sleep(
        1
    )


    neighbors = (
        get_neighbor_table()
    )


    for (
        ip,
        mac
    ) in neighbors.items():

        record = ensure_record(

            records,

            network,

            ip

        )


        if not record:

            continue


        record[
            "methods"
        ].add(
            "arp"
        )


        record["mac"] = (
            mac
        )


        vendor = lookup_mac_vendor(
            mac
        )


        if vendor:

            add_raw_candidate(

                record,

                "vendor_candidates",

                vendor,

                "mac_oui",

                74

            )


    # ========================================================
    # PASS 7 - REVERSE DNS
    # ========================================================

    current_ips = list(
        records.keys()
    )


    with concurrent.futures.ThreadPoolExecutor(

        max_workers=20

    ) as executor:

        futures = [

            executor.submit(
                reverse_dns,
                ip
            )

            for ip in current_ips

        ]


        for future in concurrent.futures.as_completed(
            futures
        ):

            try:

                ip, hostname = (
                    future.result()
                )


                if (
                    ip in records
                    and
                    hostname
                ):

                    apply_reverse_dns(

                        records[ip],

                        hostname

                    )


            except Exception:

                pass


    # ========================================================
    # PASS 8 - NETBIOS
    # ========================================================

    with concurrent.futures.ThreadPoolExecutor(

        max_workers=30

    ) as executor:

        futures = {

            executor.submit(
                netbios_names,
                ip
            ):
            ip

            for ip in records.keys()

        }


        for future in concurrent.futures.as_completed(
            futures
        ):

            ip = futures[
                future
            ]


            try:

                names = future.result()


                if names:

                    apply_nbns(

                        records[ip],

                        names

                    )


            except Exception:

                pass


    # ========================================================
    # FINAL DEVICE IDENTITIES
    # ========================================================

    devices = []


    for ip in sorted(

        records.keys(),

        key=lambda value:
            ipaddress.ip_address(
                value
            )

    ):

        record = records[ip]


        friendly = best_candidate(

            record,

            "friendly_candidates"

        )


        hostname = best_candidate(

            record,

            "hostname_candidates"

        )


        vendor = best_candidate(

            record,

            "vendor_candidates"

        )


        model = best_candidate(

            record,

            "model_candidates"

        )


        mac = normalize_mac(

            record.get(
                "mac"
            )

        )


        if not valid_mac(mac):

            mac = None


        device_type = infer_device_type(

            record,

            friendly,

            hostname,

            vendor,

            model

        )


        os_guess = infer_os(

            record,

            friendly,

            hostname,

            model,

            device_type

        )


        confidence = (
            calculate_confidence(

                record,

                friendly,

                hostname,

                vendor,

                model

            )
        )


        security_status, security_findings = (
            build_security_assessment(

                record[
                    "open_ports"
                ]

            )
        )


        fingerprint_data = {

            "gateway":
                bool(
                    record.get(
                        "gateway"
                    )
                ),

            "private_mac":
                bool(
                    mac
                    and
                    is_private_mac(
                        mac
                    )
                ),

            "reverse_dns":
                record.get(
                    "reverse_dns"
                ),

            "netbios_names":
                record.get(
                    "nbns",
                    []
                ),

            "mdns_services":
                record.get(
                    "mdns",
                    []
                ),

            "ssdp_devices":
                record.get(
                    "ssdp",
                    []
                ),

            "name_candidates":
                record.get(
                    "friendly_candidates",
                    []
                )[:10],

            "hostname_candidates":
                record.get(
                    "hostname_candidates",
                    []
                )[:10],

            "manufacturer_candidates":
                record.get(
                    "vendor_candidates",
                    []
                )[:10],

            "model_candidates":
                record.get(
                    "model_candidates",
                    []
                )[:10],

        }


        devices.append({

            "ip":
                ip,

            "mac":
                mac,

            "hostname":
                hostname,

            "friendly_name":
                friendly,

            "vendor":
                vendor,

            "model":
                model,

            "device_type":
                device_type,

            "os_guess":
                os_guess,

            "identity_confidence":
                confidence,

            "identity_sources":
                sorted(
                    record[
                        "identity_sources"
                    ]
                ),

            "fingerprint_data":
                fingerprint_data,

            "discovery_methods":
                sorted(
                    record[
                        "methods"
                    ]
                ),

            "open_ports":
                sorted(
                    record[
                        "open_ports"
                    ]
                ),

            "services":
                build_services(
                    record[
                        "open_ports"
                    ]
                ),

            "security_status":
                security_status,

            "security_findings":
                security_findings,

        })


    log(
        f"FINAL DEVICES: {len(devices)}"
    )


    for device in devices:

        log(

            "DEVICE | "
            f"{device['friendly_name'] or device['hostname'] or device['ip']} | "
            f"IP={device['ip']} | "
            f"MAC={device['mac']} | "
            f"VENDOR={device['vendor']} | "
            f"MODEL={device['model']} | "
            f"TYPE={device['device_type']} | "
            f"CONFIDENCE={device['identity_confidence']}%"

        )


    log(
        "=============================================="
    )


    return (
        devices,
        network,
        local_ip
    )


# ============================================================
# SYNC
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
            "590x610"
        )


        self.root.minsize(
            510,
            510
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
                value="Not connected"
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


        self.identified_value = (
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

                "bold"
                if bold
                else "normal"

            )

        )


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

            text="W",

            bg="#35e79a",

            fg="#042116",

            width=2,

            height=1,

            font=(
                "Arial",
                20,
                "bold"
            )

        )


        logo.pack(
            side="left"
        )


        title = tk.Frame(

            header,

            bg="#071017"

        )


        title.pack(

            side="left",

            padx=12

        )


        self.label(

            title,

            "WiFi Watch Agent",

            18,

            True

        ).pack(
            anchor="w"
        )


        self.label(

            title,

            f"Expert Device Intelligence · v{APP_VERSION}",

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
    # PAIRING
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

            pady=(10, 7)

        )


        self.label(

            self.body,

            (
                "Generate a pairing code from your "
                "WiFi Watch dashboard."
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

            fg="white",

            insertbackground="white",

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


        button = tk.Button(

            self.body,

            text="Connect",

            bg="#35e79a",

            fg="#042116",

            relief="flat",

            font=(
                "Arial",
                12,
                "bold"
            ),

            command=self.pair

        )


        button.pack(

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

            self.config = (
                claim_pairing_code(
                    code
                )
            )


            self.root.after(

                0,

                self._pair_success

            )


        except Exception as exc:

            log(
                f"Pair error: {exc}"
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
    # CONNECTED
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
                "Identified devices",
                self.identified_value
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
            name,
            variable
        ) in rows:

            row = tk.Frame(

                card,

                bg="#101f29"

            )


            row.pack(

                fill="x",

                padx=18,

                pady=9

            )


            tk.Label(

                row,

                text=name,

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

                fg="white",

                font=(
                    "Arial",
                    10,
                    "bold"
                )

            ).pack(
                side="right"
            )


        button = tk.Button(

            self.body,

            text=
                "Run Expert Network Scan",

            bg="#35e79a",

            fg="#042116",

            relief="flat",

            font=(
                "Arial",
                11,
                "bold"
            ),

            command=
                self.manual_scan

        )


        button.pack(

            fill="x",

            ipady=9,

            pady=(20, 10)

        )


        self.label(

            self.body,

            (
                "WiFi Watch combines network discovery, "
                "Bonjour, UPnP, NetBIOS and service "
                "fingerprinting to identify devices."
            ),

            9,

            False,

            "#8da2af"

        ).pack(
            pady=(5, 10)
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
            pady=(0, 15)
        )


        disconnect = tk.Button(

            self.body,

            text="Disconnect this Agent",

            bg="#13232d",

            fg="#ff8a8a",

            relief="flat",

            command=self.disconnect

        )


        disconnect.pack(

            fill="x",

            ipady=7

        )


    # ========================================================
    # MONITOR
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
                    self.status_value
                    .set(
                        "Expert scanning..."
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


            sync_devices(

                self.config,

                devices

            )


            identified = sum(

                1

                for device in devices

                if (
                    device.get(
                        "friendly_name"
                    )
                    or
                    device.get(
                        "hostname"
                    )
                    or
                    device.get(
                        "vendor"
                    )
                    or
                    device.get(
                        "model"
                    )
                )

            )


            warnings = sum(

                1

                for device in devices

                if device.get(
                    "security_status"
                )
                ==
                "warning"

            )


            reviews = sum(

                1

                for device in devices

                if device.get(
                    "security_status"
                )
                ==
                "review"

            )


            self.root.after(

                0,

                lambda:
                    self.scan_success(

                        len(devices),

                        identified,

                        str(network),

                        local_ip,

                        warnings,

                        reviews

                    )

            )


        except Exception as exc:

            log(
                f"SCAN ERROR: {exc}"
            )


            self.root.after(

                0,

                lambda:
                    self.scan_error(
                        str(exc)
                    )

            )


        finally:

            self.scan_lock.release()


    def scan_success(
        self,
        count,
        identified,
        network,
        local_ip,
        warnings,
        reviews
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


        self.identified_value.set(

            f"{identified} / {count}"

        )


        if warnings:

            self.security_value.set(

                f"{warnings} warning(s), "
                f"{reviews} review"

            )


        elif reviews:

            self.security_value.set(

                f"{reviews} item(s) to review"

            )


        else:

            self.security_value.set(

                "No obvious issues"

            )


        self.scan_value.set(

            time.strftime(
                "%H:%M:%S"
            )

        )


    def scan_error(
        self,
        error
    ):

        self.status_value.set(
            "Error"
        )


        log(
            error
        )


    # ========================================================
    # DISCONNECT
    # ========================================================

    def disconnect(self):

        if not messagebox.askyesno(

            "Disconnect Agent",

            "Disconnect this computer from WiFi Watch?"

        ):

            return


        self.stop_event.set()


        delete_config()


        self.config = {}


        self.show_pairing()


    def close(self):

        self.stop_event.set()


        self.root.destroy()


    def run(self):

        self.root.mainloop()


# ============================================================
# START
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
                "Supabase URL and publishable "
                "key have not been configured."
            )

        )


        root.destroy()


        raise SystemExit(1)


    log(

        f"Starting WiFi Watch Agent "
        f"{APP_VERSION}"

    )


    app = WiFiWatchApp()

    app.run()
