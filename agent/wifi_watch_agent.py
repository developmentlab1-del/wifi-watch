import concurrent.futures
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
    Zeroconf,
    ServiceBrowser,
    ServiceListener,
    IPVersion,
)


# ============================================================
# WIFI WATCH AGENT
# ============================================================

APP_VERSION = "0.1.3"

# ============================================================
# USE THE SAME VALUES AS YOUR WEBSITE
# ONLY USE THE PUBLISHABLE KEY
# ============================================================

SUPABASE_URL = "https://ephdcwogebxfsidytmrj.supabase.co"

SUPABASE_KEY = "sb_publishable_L9TUAFyJ_S0l81UDNi8imw_FVTYm4cI"


SCAN_INTERVAL = 30
REQUEST_TIMEOUT = 20

MAX_WORKERS = 80


COMMON_TCP_PORTS = [

    22,       # SSH

    53,       # DNS

    80,       # HTTP

    139,      # NetBIOS

    443,      # HTTPS

    445,      # SMB

    554,      # RTSP / cameras

    631,      # printers

    1883,     # MQTT

    5000,

    5001,

    7000,     # AirPlay

    8000,

    8080,

    8443,

    9100,     # printers

    32400,    # Plex

    62078,    # Apple devices
]


MDNS_SERVICES = [

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

]


# ============================================================
# APPLICATION FOLDER
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
            base /
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
    APP_FOLDER /
    "agent.json"
)

LOG_FILE = (
    APP_FOLDER /
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

            details = (
                response.json()
            )

        except Exception:

            details = (
                response.text
            )


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
            result["network_id"]

    }


    save_config(
        config
    )


    log(
        "Pairing successful."
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
                APP_VERSION

        }

    )


# ============================================================
# COMMAND PATH
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


            number = int(
                part,
                16
            )


            result.append(
                f"{number:02x}"
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

        "ff:ff:ff:ff:ff:ff"

    ):

        return False


    try:

        first_byte = int(
            mac.split(":")[0],
            16
        )


        # multicast/broadcast-style
        # addresses are not client devices
        if first_byte & 1:

            return False


    except Exception:

        return False


    return True


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
                "8.8.8.8",
                80
            )
        )


        return (
            sock.getsockname()[0]
        )


    finally:

        sock.close()


def get_network_details():

    local_ip = (
        get_primary_local_ip()
    )


    interface_name = None

    netmask = None

    own_mac = None


    for (
        interface,
        addresses
    ) in (
        psutil
        .net_if_addrs()
        .items()
    ):

        found = False


        for address in addresses:

            if (

                address.family ==
                socket.AF_INET

                and

                address.address ==
                local_ip

            ):

                interface_name = (
                    interface
                )

                netmask = (
                    address.netmask
                )

                found = True

                break


        if not found:

            continue


        for address in addresses:

            if (
                address.family ==
                psutil.AF_LINK
            ):

                own_mac = (
                    normalize_mac(
                        address.address
                    )
                )

                break


        break


    if not netmask:

        netmask = (
            "255.255.255.0"
        )


    network = (
        ipaddress.ip_network(

            f"{local_ip}/{netmask}",

            strict=False

        )
    )


    # Keep this version safe and fast.
    # If network is larger than /24,
    # scan current /24 segment.

    if (
        network.num_addresses > 256
    ):

        network = (
            ipaddress.ip_network(

                f"{local_ip}/24",

                strict=False

            )
        )


    log(

        "Network: "
        f"interface={interface_name}, "
        f"IP={local_ip}, "
        f"subnet={network}, "
        f"MAC={own_mac}"

    )


    return {

        "local_ip":
            local_ip,

        "network":
            network,

        "interface":
            interface_name,

        "own_mac":
            own_mac

    }


# ============================================================
# ARP SEED
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
# ICMP DISCOVERY
# ============================================================

def ping_host(ip):

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

            str(ip)

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

            str(ip)

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

            str(ip)

        ]


    try:

        result = subprocess.run(

            command,

            stdout=subprocess.DEVNULL,

            stderr=subprocess.DEVNULL,

            timeout=2,

            creationflags=
                creation_flags

        )


        if result.returncode == 0:

            return str(ip)


    except Exception:
        pass


    return None


# ============================================================
# TCP DISCOVERY
# ============================================================

def tcp_probe(ip):

    ip = str(ip)


    for port in COMMON_TCP_PORTS:

        sock = socket.socket(

            socket.AF_INET,

            socket.SOCK_STREAM

        )


        sock.settimeout(
            0.15
        )


        try:

            result = sock.connect_ex(

                (
                    ip,
                    port
                )

            )


            # 0 = connection accepted.
            #
            # Other immediate responses can
            # still cause ARP resolution;
            # we'll collect those later from
            # the neighbor table.

            if result == 0:

                return ip


        except Exception:
            pass


        finally:

            try:

                sock.close()

            except Exception:
                pass


    return None


# ============================================================
# MACOS ARP
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
    # aa:b:c:12:3:f
    #
    # not necessarily:
    #
    # aa:0b:0c:12:03:0f

    regex = re.compile(

        r"\((\d+\.\d+\.\d+\.\d+)\)"
        r"\s+at\s+"
        r"([0-9A-Fa-f:]+)"

    )


    for (
        ip,
        raw_mac
    ) in regex.findall(
        output
    ):

        mac = normalize_mac(
            raw_mac
        )


        if valid_mac(mac):

            result[ip] = mac


    return result


# ============================================================
# WINDOWS ARP
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


    regex = re.compile(

        r"(\d+\.\d+\.\d+\.\d+)"
        r"\s+"
        r"([0-9A-Fa-f-]{11,17})"

    )


    for (
        ip,
        raw_mac
    ) in regex.findall(
        output
    ):

        mac = normalize_mac(
            raw_mac
        )


        if valid_mac(mac):

            result[ip] = mac


    return result


# ============================================================
# LINUX NEIGHBOR
# ============================================================

def get_linux_neighbors():

    binary = get_command(

        "ip",

        [
            "/usr/sbin/ip",
            "/usr/bin/ip",
            "/sbin/ip"
        ]

    )


    result = {}


    try:

        output = subprocess.check_output(

            [
                binary,
                "neigh",
                "show"
            ],

            text=True,

            stderr=subprocess.DEVNULL

        )


        regex = re.compile(

            r"(\d+\.\d+\.\d+\.\d+)"
            r".*?\slladdr\s"
            r"([0-9A-Fa-f:]+)"

        )


        for (
            ip,
            raw_mac
        ) in regex.findall(
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

    system = platform.system()


    try:

        if system == "Darwin":

            devices = (
                get_macos_neighbors()
            )


        elif system == "Windows":

            devices = (
                get_windows_neighbors()
            )


        else:

            devices = (
                get_linux_neighbors()
            )


        log(

            f"ARP/neighbor discovery: "
            f"{len(devices)} device(s)"

        )


        return devices


    except Exception as exc:

        log(
            f"Neighbor error: {exc}"
        )


        return {}


# ============================================================
# SSDP / UPNP
# ============================================================

def discover_ssdp():

    found = set()


    message = (

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

                    message,

                    (
                        "239.255.255.250",
                        1900
                    )

                )

            except Exception:
                pass


        deadline = (
            time.time() + 3
        )


        while (
            time.time() < deadline
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

class MDNSListener(
    ServiceListener
):

    def __init__(
        self,
        results
    ):

        self.results = results


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

                    timeout=800

                )
            )


            if not info:

                return


            hostname = (

                info.server
                or
                name

            ).rstrip(".")


            for ip in (
                info.parsed_addresses(
                    IPVersion.V4Only
                )
            ):

                self.results[ip] = (
                    hostname
                )


        except Exception:
            pass


def discover_mdns():

    results = {}


    try:

        zeroconf = Zeroconf(

            ip_version=
                IPVersion.V4Only

        )


        listener = MDNSListener(
            results
        )


        browsers = []


        for service in MDNS_SERVICES:

            try:

                browsers.append(

                    ServiceBrowser(

                        zeroconf,

                        service,

                        listener

                    )

                )

            except Exception:
                pass


        time.sleep(
            4
        )


        for browser in browsers:

            try:

                browser.cancel()

            except Exception:
                pass


        zeroconf.close()


    except Exception as exc:

        log(
            f"mDNS error: {exc}"
        )


    log(

        "mDNS discovery: "
        f"{len(results)} device(s)"

    )


    return results


# ============================================================
# SCAN NETWORK
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


    discovered_ips = {
        local_ip
    }


    names = {

        local_ip:
            socket.gethostname()

    }


    log(

        f"Starting multi-method scan "
        f"of {network}"

    )


    # ========================================================
    # PASS 1 - FORCE NEIGHBOR RESOLUTION
    # ========================================================

    with (
        concurrent.futures
        .ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        )
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

    ping_hits = set()


    with (
        concurrent.futures
        .ThreadPoolExecutor(
            max_workers=MAX_WORKERS
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


            except Exception:
                pass


    discovered_ips.update(
        ping_hits
    )


    log(

        "Ping discovery: "
        f"{len(ping_hits)} device(s)"

    )


    # ========================================================
    # PASS 3 - TCP SERVICES
    # ========================================================

    tcp_hits = set()


    with (
        concurrent.futures
        .ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        )
    ) as executor:

        futures = [

            executor.submit(
                tcp_probe,
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

                    tcp_hits.add(
                        result
                    )


            except Exception:
                pass


    discovered_ips.update(
        tcp_hits
    )


    log(

        "TCP discovery: "
        f"{len(tcp_hits)} device(s)"

    )


    # ========================================================
    # PASS 4 - SSDP
    # ========================================================

    ssdp_hits = (
        discover_ssdp()
    )


    for ip in ssdp_hits:

        try:

            if (
                ipaddress.ip_address(ip)
                in network
            ):

                discovered_ips.add(
                    ip
                )

        except Exception:
            pass


    # ========================================================
    # PASS 5 - MDNS
    # ========================================================

    mdns_hits = (
        discover_mdns()
    )


    for (
        ip,
        hostname
    ) in mdns_hits.items():

        try:

            if (
                ipaddress.ip_address(ip)
                in network
            ):

                discovered_ips.add(
                    ip
                )

                names[ip] = (
                    hostname
                )

        except Exception:
            pass


    # ========================================================
    # ALLOW ARP CACHE TO SETTLE
    # ========================================================

    time.sleep(
        1.5
    )


    # ========================================================
    # PASS 6 - READ ACTUAL ARP TABLE
    # ========================================================

    neighbors = (
        get_neighbor_table()
    )


    for ip in neighbors:

        try:

            if (
                ipaddress.ip_address(ip)
                in network
            ):

                discovered_ips.add(
                    ip
                )

        except Exception:
            pass


    # ========================================================
    # BUILD RESULT
    # ========================================================

    devices = []


    for ip in sorted(

        discovered_ips,

        key=lambda value:
            ipaddress.ip_address(
                value
            )

    ):

        mac = (
            neighbors.get(ip)
        )


        if (
            ip == local_ip
            and
            own_mac
        ):

            mac = own_mac


        mac = normalize_mac(
            mac
        )


        # Supabase currently identifies
        # devices by MAC, therefore only
        # upload devices whose MAC was
        # resolved.

        if not valid_mac(mac):

            log(

                f"Discovered IP {ip}, "
                "but no valid MAC yet."

            )

            continue


        hostname = (
            names.get(ip)
        )


        devices.append({

            "ip":
                ip,

            "mac":
                mac,

            "hostname":
                hostname,

            "vendor":
                None

        })


    log(
        "================================"
    )


    log(
        f"FINAL DEVICE COUNT: "
        f"{len(devices)}"
    )


    for device in devices:

        log(

            "DEVICE | "
            f"{device['ip']} | "
            f"{device['mac']} | "
            f"{device['hostname']}"

        )


    log(
        "================================"
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
                config[
                    "agent_secret"
                ],

            "p_devices":
                devices

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
            "550x550"
        )


        self.root.minsize(
            490,
            470
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

                (
                    "bold"
                    if bold
                    else "normal"
                )

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


        wrap = tk.Frame(

            header,

            bg="#071017"

        )


        wrap.pack(

            side="left",

            padx=12

        )


        self.label(

            wrap,

            "WiFi Watch Agent",

            18,

            True

        ).pack(
            anchor="w"
        )


        self.label(

            wrap,

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
                "from your WiFi Watch "
                "website and enter it below."
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
                "Last scan",
                self.scan_value
            )

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

                fg="white",

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
                "WiFi Watch automatically "
                f"rescans every "
                f"{SCAN_INTERVAL} seconds."
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

            relief="flat",

            command=
                self.disconnect

        )


        disconnect.pack(

            fill="x",

            ipady=7

        )


    # ========================================================
    # SCANNING
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

                count = (
                    result.get(

                        "devices_seen",

                        len(devices)

                    )
                )

            else:

                count = len(
                    devices
                )


            self.root.after(

                0,

                lambda:
                    self.scan_success(

                        count,

                        str(network),

                        local_ip

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
        network,
        local_ip
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
            f"UI error: {error}"
        )


    # ========================================================
    # DISCONNECT
    # ========================================================

    def disconnect(self):

        confirmed = (
            messagebox.askyesno(

                "Disconnect Agent",

                (
                    "Disconnect this "
                    "computer from "
                    "WiFi Watch?"
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
# START
# ============================================================

if __name__ == "__main__":

    if (

        "YOUR_REAL_" in
        SUPABASE_URL

        or

        "YOUR_REAL_" in
        SUPABASE_KEY

    ):

        root = tk.Tk()

        root.withdraw()


        messagebox.showerror(

            "WiFi Watch",

            (
                "Configure the Supabase "
                "URL and publishable key."
            )

        )


        root.destroy()


        raise SystemExit(1)


    log(

        "Starting WiFi Watch Agent "
        f"{APP_VERSION} on "
        f"{platform.system()}"

    )


    app = WiFiWatchApp()

    app.run()
