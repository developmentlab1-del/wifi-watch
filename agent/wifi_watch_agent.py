import concurrent.futures
import ipaddress
import json
import os
import platform
import re
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
# WIFI WATCH
# ============================================================

APP_VERSION = "0.1.0"

SUPABASE_URL = "YOUR_SUPABASE_URL"
SUPABASE_KEY = "YOUR_SUPABASE_PUBLISHABLE_KEY"

SCAN_INTERVAL = 30
REQUEST_TIMEOUT = 20


# ============================================================
# LOCAL CONFIG
# ============================================================

def get_config_path():

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

    return folder / "agent.json"


CONFIG_FILE = get_config_path()


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

    except Exception:
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

    except Exception:
        pass


# ============================================================
# SUPABASE
# ============================================================

def rpc(
    function_name,
    payload
):

    url = (
        f"{SUPABASE_URL}"
        f"/rest/v1/rpc/{function_name}"
    )

    headers = {
        "apikey": SUPABASE_KEY,
        "Content-Type": "application/json",
    }

    response = requests.post(
        url,
        headers=headers,
        json=payload,
        timeout=REQUEST_TIMEOUT
    )

    if not response.ok:

        try:
            message = response.json()
        except Exception:
            message = response.text

        raise RuntimeError(
            f"{response.status_code}: {message}"
        )

    if not response.content:
        return None

    return response.json()


# ============================================================
# PAIR AGENT
# ============================================================

def claim_pairing_code(code):

    result = rpc(
        "claim_pairing_code",
        {
            "p_code": code.strip(),
            "p_name": "WiFi Watch Agent",
            "p_platform": platform.system(),
            "p_hostname": socket.gethostname(),
            "p_version": APP_VERSION,
        }
    )

    if not result:
        raise RuntimeError(
            "Pairing failed."
        )

    required = (
        "agent_id",
        "agent_secret",
        "network_id"
    )

    for key in required:

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

    return config


# ============================================================
# AGENT HEARTBEAT
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
# NETWORK INFORMATION
# ============================================================

def get_primary_local_ip():

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    try:

        sock.connect(
            ("8.8.8.8", 80)
        )

        return sock.getsockname()[0]

    finally:

        sock.close()


def get_network_details():

    local_ip = get_primary_local_ip()

    interface_name = None
    netmask = None
    own_mac = None

    interfaces = (
        psutil.net_if_addrs()
    )

    for name, addresses in interfaces.items():

        found_ip = False

        for address in addresses:

            if (
                address.family
                == socket.AF_INET
                and
                address.address
                == local_ip
            ):

                interface_name = name
                netmask = address.netmask
                found_ip = True
                break

        if not found_ip:
            continue

        for address in addresses:

            if (
                address.family
                == psutil.AF_LINK
            ):

                own_mac = (
                    address.address
                    .replace("-", ":")
                    .lower()
                )

                break

        break


    if not netmask:
        netmask = "255.255.255.0"


    network = ipaddress.ip_network(
        f"{local_ip}/{netmask}",
        strict=False
    )


    # Safety / performance:
    # MVP scans at most the local /24.
    if network.num_addresses > 256:

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
# PING
# ============================================================

def ping_host(ip):

    system = platform.system()

    if system == "Windows":

        command = [
            "ping",
            "-n",
            "1",
            "-w",
            "700",
            str(ip)
        ]

        creation_flags = (
            subprocess.CREATE_NO_WINDOW
            if hasattr(
                subprocess,
                "CREATE_NO_WINDOW"
            )
            else 0
        )

    elif system == "Darwin":

        command = [
            "ping",
            "-c",
            "1",
            "-W",
            "700",
            str(ip)
        ]

        creation_flags = 0

    else:

        command = [
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            str(ip)
        ]

        creation_flags = 0


    try:

        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            creationflags=creation_flags
        )

        return (
            str(ip)
            if result.returncode == 0
            else None
        )

    except Exception:
        return None


# ============================================================
# ARP TABLE
# ============================================================

def get_arp_table():

    try:

        creation_flags = 0

        if (
            platform.system()
            == "Windows"
            and
            hasattr(
                subprocess,
                "CREATE_NO_WINDOW"
            )
        ):

            creation_flags = (
                subprocess.CREATE_NO_WINDOW
            )


        output = subprocess.check_output(
            ["arp", "-a"],
            text=True,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags
        )

    except Exception:
        return {}


    devices = {}


    if (
        platform.system()
        == "Windows"
    ):

        pattern = re.compile(
            r"(\d+\.\d+\.\d+\.\d+)"
            r"\s+"
            r"([0-9a-fA-F-]{17})"
        )


        for ip, mac in pattern.findall(
            output
        ):

            devices[ip] = (
                mac
                .replace("-", ":")
                .lower()
            )


    else:

        pattern = re.compile(
            r"\((\d+\.\d+\.\d+\.\d+)\)"
            r"\s+at\s+"
            r"([0-9a-fA-F:]{17})"
        )


        for ip, mac in pattern.findall(
            output
        ):

            devices[ip] = (
                mac.lower()
            )


    return devices


# ============================================================
# MAC VALIDATION
# ============================================================

def valid_mac(mac):

    if not mac:
        return False

    mac = (
        mac
        .replace("-", ":")
        .lower()
    )

    if not re.fullmatch(
        r"[0-9a-f]{2}"
        r"(:[0-9a-f]{2}){5}",
        mac
    ):
        return False


    if mac in (
        "00:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff"
    ):
        return False


    # Ignore multicast MAC addresses.
    try:

        first_byte = int(
            mac.split(":")[0],
            16
        )

        if first_byte & 1:
            return False

    except Exception:
        return False


    return True


# ============================================================
# SCAN NETWORK
# ============================================================

def scan_network():

    info = get_network_details()

    network = info["network"]

    local_ip = info["local_ip"]

    own_mac = info["own_mac"]


    hosts = list(
        network.hosts()
    )


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

            result = future.result()

            if result:
                active_ips.add(
                    result
                )


    # Give ARP cache a moment.
    time.sleep(0.5)


    arp_table = get_arp_table()


    # ARP can find devices that didn't
    # answer ICMP/ping.
    for ip in arp_table:

        try:

            if (
                ipaddress.ip_address(ip)
                in network
            ):

                active_ips.add(ip)

        except Exception:
            pass


    devices = []


    for ip in sorted(
        active_ips,
        key=lambda x:
            ipaddress.ip_address(x)
    ):

        mac = arp_table.get(ip)


        # Add this computer manually.
        if (
            ip == local_ip
            and
            own_mac
        ):

            mac = own_mac


        if not valid_mac(mac):
            continue


        hostname = None


        if ip == local_ip:

            hostname = (
                socket.gethostname()
            )


        devices.append({
            "ip":
                ip,

            "mac":
                mac.lower(),

            "hostname":
                hostname,

            "vendor":
                None,
        })


    # Ensure local computer appears.
    if (
        own_mac
        and
        valid_mac(own_mac)
        and
        not any(
            d["mac"]
            == own_mac.lower()
            for d in devices
        )
    ):

        devices.append({
            "ip":
                local_ip,

            "mac":
                own_mac.lower(),

            "hostname":
                socket.gethostname(),

            "vendor":
                None,
        })


    return (
        devices,
        network,
        local_ip
    )


# ============================================================
# UPLOAD SCAN
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
            "500x480"
        )

        self.root.minsize(
            460,
            430
        )

        self.root.configure(
            bg="#071017"
        )


        self.stop_event = (
            threading.Event()
        )

        self.monitor_thread = None

        self.config = load_config()


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
    # HELPERS
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


    def is_paired(self):

        return (
            self.config.get(
                "agent_id"
            )
            and
            self.config.get(
                "agent_secret"
            )
        )


    # --------------------------------------------------------
    # UI
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
            self.body.winfo_children()
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
                "Create a pairing code on the "
                "WiFi Watch website and enter it below."
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
                16,
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
            activebackground="#35e79a",
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


        self.pair_status = self.label(
            self.body,
            "",
            10,
            False,
            "#ffbd67"
        )

        self.pair_status.pack(
            pady=15
        )


        self.label(
            self.body,
            (
                "Only connect WiFi Watch to a "
                "network you own or are authorized "
                "to administer."
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


        status_row = tk.Frame(
            self.body,
            bg="#071017"
        )

        status_row.pack(
            fill="x",
            pady=(8, 20)
        )


        self.label(
            status_row,
            "● Connected",
            13,
            True,
            "#35e79a"
        ).pack(
            side="left"
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


        for label_text, variable in rows:

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
            activebackground="#35e79a",
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
            pady=(3, 18)
        )


        disconnect = tk.Button(
            self.body,
            text="Disconnect this Agent",
            bg="#13232d",
            fg="#ff8a8a",
            activebackground="#13232d",
            relief="flat",
            command=self.disconnect
        )

        disconnect.pack(
            fill="x",
            ipady=7
        )


    # --------------------------------------------------------
    # MONITOR
    # --------------------------------------------------------

    def start_monitoring(self):

        if (
            self.monitor_thread
            and
            self.monitor_thread.is_alive()
        ):
            return


        self.stop_event.clear()


        self.monitor_thread = (
            threading.Thread(
                target=self.monitor_loop,
                daemon=True
            )
        )


        self.monitor_thread.start()


    def monitor_loop(self):

        while not self.stop_event.is_set():

            self.perform_scan()

            self.stop_event.wait(
                SCAN_INTERVAL
            )


    def manual_scan(self):

        threading.Thread(
            target=self.perform_scan,
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


            devices, network, local_ip = (
                scan_network()
            )


            result = sync_devices(
                self.config,
                devices
            )


            count = (
                result.get(
                    "devices_seen",
                    len(devices)
                )
                if isinstance(
                    result,
                    dict
                )
                else len(devices)
            )


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
            network
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

        print(
            "WiFi Watch scan error:",
            error
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


    def run(self):

        self.root.mainloop()


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    if (
        "YOUR_SUPABASE" in
        SUPABASE_URL
        or
        "YOUR_SUPABASE" in
        SUPABASE_KEY
    ):

        root = tk.Tk()
        root.withdraw()

        messagebox.showerror(
            "WiFi Watch",
            (
                "Supabase URL and "
                "publishable key have not "
                "been configured."
            )
        )

        root.destroy()

        raise SystemExit(1)


    app = WiFiWatchApp()

    app.run()
