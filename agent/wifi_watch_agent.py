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


# ============================================================
# WIFI WATCH AGENT
# ============================================================

APP_VERSION = "0.1.2"

# ------------------------------------------------------------
# IMPORTANT:
# Put the SAME Supabase Project URL + PUBLISHABLE KEY
# used by your index.html here.
#
# Publishable key is OK inside the application.
# NEVER use service_role / sb_secret_ here.
# ------------------------------------------------------------

SUPABASE_URL = "https://ephdcwogebxfsidytmrj.supabase.co"

SUPABASE_KEY = "sb_publishable_L9TUAFyJ_S0l81UDNi8imw_FVTYm4cI"


SCAN_INTERVAL = 30
REQUEST_TIMEOUT = 20


# ============================================================
# APPLICATION DATA
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

        folder = base / "WiFiWatch"

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

            return json.load(file)

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

            error_message = (
                response.json()
            )

        except Exception:

            error_message = (
                response.text
            )

        raise RuntimeError(
            f"{response.status_code}: "
            f"{error_message}"
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

    for key in (
        "agent_id",
        "agent_secret",
        "network_id"
    ):

        if key not in result:

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

    save_config(config)

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
# COMMAND PATH HELPER
# ============================================================

def get_command(
    name,
    candidates
):

    found = shutil.which(name)

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

    mac = (
        str(mac)
        .strip()
        .lower()
        .replace("-", ":")
    )

    parts = mac.split(":")

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

    mac = normalize_mac(mac)

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

        # Multicast MAC
        if first_byte & 1:

            return False

    except Exception:

        return False

    return True


# ============================================================
# PRIMARY NETWORK
# ============================================================

def get_primary_local_ip():

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    try:

        # UDP connect does not actually
        # need to send data.
        sock.connect(
            ("8.8.8.8", 80)
        )

        ip = (
            sock.getsockname()[0]
        )

        return ip

    finally:

        sock.close()


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

    for name, addresses in (
        interfaces.items()
    ):

        found_interface = False

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

                found_interface = True

                break

        if not found_interface:

            continue

        for address in addresses:

            if (
                address.family
                == psutil.AF_LINK
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

    # Safety/performance:
    # Do not scan more than /24
    # in this version.
    if network.num_addresses > 256:

        network = (
            ipaddress.ip_network(
                f"{local_ip}/24",
                strict=False
            )
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
# SEED ARP / NEIGHBOR CACHE
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

        # Any local IP packet causes the OS
        # to attempt ARP resolution.
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

    system = platform.system()

    creation_flags = 0

    if system == "Darwin":

        ping_binary = get_command(

            "ping",

            [
                "/sbin/ping",
                "/usr/bin/ping"
            ]

        )

        command = [

            ping_binary,

            "-c",
            "1",

            "-W",
            "700",

            str(ip)

        ]

    elif system == "Windows":

        ping_binary = get_command(
            "ping",
            []
        )

        command = [

            ping_binary,

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

        ping_binary = get_command(

            "ping",

            [
                "/usr/bin/ping",
                "/bin/ping"
            ]

        )

        command = [

            ping_binary,

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
# WINDOWS ARP
# ============================================================

def get_windows_arp_table():

    arp_binary = get_command(
        "arp",
        []
    )

    creation_flags = 0

    if hasattr(
        subprocess,
        "CREATE_NO_WINDOW"
    ):

        creation_flags = (
            subprocess.CREATE_NO_WINDOW
        )

    output = subprocess.check_output(

        [
            arp_binary,
            "-a"
        ],

        text=True,

        stderr=subprocess.DEVNULL,

        creationflags=
            creation_flags

    )

    devices = {}

    pattern = re.compile(

        r"(\d+\.\d+\.\d+\.\d+)"
        r"\s+"
        r"([0-9A-Fa-f-]{11,17})"

    )

    for ip, raw_mac in (
        pattern.findall(output)
    ):

        mac = normalize_mac(
            raw_mac
        )

        if valid_mac(mac):

            devices[ip] = mac

    return devices


# ============================================================
# MACOS ARP
# ============================================================

def get_macos_arp_table():

    arp_binary = get_command(

        "arp",

        [
            "/usr/sbin/arp",
            "/sbin/arp"
        ]

    )

    output = subprocess.check_output(

        [
            arp_binary,
            "-an"
        ],

        text=True,

        stderr=subprocess.DEVNULL

    )

    devices = {}

    # Important:
    # macOS can print MAC octets
    # without leading zeroes:
    #
    # 8:3a:12:4:b:10
    #
    # so DO NOT require exactly
    # 17 characters.

    pattern = re.compile(

        r"\((\d+\.\d+\.\d+\.\d+)\)"
        r"\s+at\s+"
        r"([0-9A-Fa-f:]+)"

    )

    for ip, raw_mac in (
        pattern.findall(output)
    ):

        mac = normalize_mac(
            raw_mac
        )

        if valid_mac(mac):

            devices[ip] = mac

    return devices


# ============================================================
# LINUX NEIGHBOR TABLE
# ============================================================

def get_linux_neighbor_table():

    devices = {}

    # Prefer "ip neigh"
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

        for ip, raw_mac in (
            pattern.findall(output)
        ):

            mac = normalize_mac(
                raw_mac
            )

            if valid_mac(mac):

                devices[ip] = mac

        if devices:

            return devices

    except Exception:
        pass

    # Fallback to arp
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

        for ip, raw_mac in (
            pattern.findall(output)
        ):

            mac = normalize_mac(
                raw_mac
            )

            if valid_mac(mac):

                devices[ip] = mac

    except Exception:
        pass

    return devices


# ============================================================
# ARP / NEIGHBOR TABLE
# ============================================================

def get_arp_table():

    system = platform.system()

    try:

        if system == "Windows":

            devices = (
                get_windows_arp_table()
            )

        elif system == "Darwin":

            devices = (
                get_macos_arp_table()
            )

        else:

            devices = (
                get_linux_neighbor_table()
            )

        log(
            "Neighbor table contains "
            f"{len(devices)} valid devices."
        )

        return devices

    except Exception as exc:

        log(
            f"Neighbor table error: {exc}"
        )

        return {}


# ============================================================
# HOSTNAME
# ============================================================

def resolve_hostname(ip):

    try:

        hostname = (
            socket.gethostbyaddr(ip)[0]
        )

        return hostname

    except Exception:

        return None


# ============================================================
# LOCAL NETWORK SCAN
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

    log(
        f"Starting scan of "
        f"{len(hosts)} addresses."
    )


    # --------------------------------------------------------
    # 1. Seed ARP cache
    # --------------------------------------------------------

    with (
        concurrent.futures
        .ThreadPoolExecutor(
            max_workers=64
        )
    ) as executor:

        list(
            executor.map(
                seed_neighbor,
                hosts
            )
        )


    # --------------------------------------------------------
    # 2. Ping in parallel
    # --------------------------------------------------------

    active_ips = set()

    with (
        concurrent.futures
        .ThreadPoolExecutor(
            max_workers=64
        )
    ) as executor:

        futures = [

            executor.submit(
                ping_host,
                host
            )

            for host in hosts

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

                    active_ips.add(
                        result
                    )

            except Exception:
                pass


    log(
        "Ping detected "
        f"{len(active_ips)} "
        "responsive IP addresses."
    )


    # Give macOS / OS ARP cache
    # time to populate.
    time.sleep(
        1.0
    )


    # --------------------------------------------------------
    # 3. Read neighbor table
    # --------------------------------------------------------

    arp_table = (
        get_arp_table()
    )


    # Devices do NOT need to answer ping.
    # If ARP resolved them, include them.

    for ip in arp_table:

        try:

            address = (
                ipaddress.ip_address(ip)
            )

            if address in network:

                active_ips.add(ip)

        except Exception:
            pass


    # Always include this computer.
    active_ips.add(
        local_ip
    )


    # --------------------------------------------------------
    # 4. Build device list
    # --------------------------------------------------------

    devices = []


    for ip in sorted(

        active_ips,

        key=lambda value:
            ipaddress.ip_address(
                value
            )

    ):

        mac = (
            arp_table.get(ip)
        )


        if (
            ip == local_ip
            and own_mac
        ):

            mac = own_mac


        mac = normalize_mac(
            mac
        )


        if not valid_mac(mac):

            log(
                f"Skipping {ip}: "
                "no valid MAC address."
            )

            continue


        hostname = None


        if ip == local_ip:

            hostname = (
                socket.gethostname()
            )

        else:

            # Reverse DNS can sometimes
            # provide useful device names.
            try:

                old_timeout = (
                    socket.getdefaulttimeout()
                )

                socket.setdefaulttimeout(
                    0.35
                )

                hostname = (
                    resolve_hostname(ip)
                )

                socket.setdefaulttimeout(
                    old_timeout
                )

            except Exception:
                pass


        devices.append({

            "ip":
                ip,

            "mac":
                mac,

            "hostname":
                hostname,

            "vendor":
                None,

        })


    log(
        "Scan finished with "
        f"{len(devices)} devices."
    )


    for device in devices:

        log(
            "DEVICE "
            f"ip={device['ip']} "
            f"mac={device['mac']} "
            f"hostname="
            f"{device['hostname']}"
        )


    return (
        devices,
        network,
        local_ip
    )


# ============================================================
# SEND DEVICE SCAN
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
                devices,

        }

    )


# ============================================================
# GUI APPLICATION
# ============================================================

class WiFiWatchApp:

    def __init__(self):

        self.root = tk.Tk()

        self.root.title(
            "WiFi Watch Agent"
        )

        self.root.geometry(
            "540x520"
        )

        self.root.minsize(
            480,
            450
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


    # --------------------------------------------------------
    # COMMON LABEL
    # --------------------------------------------------------

    def label(
        self,
        parent,
        text="",
        size=12,
        bold=False,
        color="#ffffff"
    ):

        font = (

            "Arial",

            size,

            "bold"
            if bold
            else "normal"

        )

        return tk.Label(

            parent,

            text=text,

            bg="#071017",

            fg=color,

            font=font

        )


    # --------------------------------------------------------
    # PAIRED?
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # UI SHELL
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # PAIRING SCREEN
    # --------------------------------------------------------

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
                "dashboard and enter it below."
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

            insertbackground="#ffffff",

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
                "Only use WiFi Watch on "
                "networks you own or are "
                "authorized to administer."
            ),

            9,

            False,

            "#66808e"

        ).pack(

            side="bottom",

            pady=10

        )


    # --------------------------------------------------------
    # PAIR
    # --------------------------------------------------------

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

            target=self._pair_worker,

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


    # --------------------------------------------------------
    # CONNECTED SCREEN
    # --------------------------------------------------------

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
            ),

        ]


        for (
            label_text,
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

                text=label_text,

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

                textvariable=variable,

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

            text="Scan Now",

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

            command=self.manual_scan

        )

        scan_button.pack(

            fill="x",

            ipady=8,

            pady=(20, 10)

        )


        self.label(

            self.body,

            (
                "Automatic monitoring is ON. "
                f"WiFi Watch scans approximately "
                f"every {SCAN_INTERVAL} seconds."
            ),

            9,

            False,

            "#8da2af"

        ).pack(
            pady=(3, 8)
        )


        self.label(

            self.body,

            (
                "Diagnostic log: "
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

            text="Disconnect this Agent",

            bg="#13232d",

            fg="#ff8a8a",

            activebackground=
                "#13232d",

            relief="flat",

            command=self.disconnect

        )

        disconnect.pack(

            fill="x",

            ipady=7

        )


    # --------------------------------------------------------
    # MONITORING
    # --------------------------------------------------------

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


        self.root.after(

            0,

            lambda:
                self.status_value.set(
                    "Scanning..."
                )

        )


        try:

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

                count = len(devices)


            self.root.after(

                0,

                lambda:
                    self.update_scan_success(

                        count,

                        str(network),

                        local_ip

                    )

            )


        except Exception as exc:

            log(
                f"Scan error: {exc}"
            )


            self.root.after(

                0,

                lambda:
                    self.update_scan_error(
                        str(exc)
                    )

            )


    def update_scan_success(
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


    def update_scan_error(
        self,
        error
    ):

        self.status_value.set(
            "Error"
        )


        log(
            f"UI scan error: {error}"
        )


    # --------------------------------------------------------
    # DISCONNECT
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # CLOSE
    # --------------------------------------------------------

    def close(self):

        self.stop_event.set()


        self.root.destroy()


    # --------------------------------------------------------
    # RUN
    # --------------------------------------------------------

    def run(self):

        self.root.mainloop()


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    if (
        "YOUR_SUPABASE"
        in SUPABASE_URL
        or
        "YOUR_SUPABASE"
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
        f"{APP_VERSION} on "
        f"{platform.system()}."
    )


    app = WiFiWatchApp()

    app.run()
