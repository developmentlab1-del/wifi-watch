import concurrent.futures
import errno
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import webbrowser
import xml.etree.ElementTree as ET
from pathlib import Path

import tkinter as tk
from tkinter import messagebox

import psutil
import requests
import urllib3

from zeroconf import (
    IPVersion,
    ServiceBrowser,
    ServiceListener,
    Zeroconf,
)


# ============================================================
# OPTIONAL OFFLINE MAC VENDOR DATABASE
# ============================================================

try:

    from manuf import manuf

    MAC_VENDOR_PARSER = (
        manuf.MacParser()
    )

except Exception:

    MAC_VENDOR_PARSER = None


urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)



# ============================================================
# WIFI WATCH
# ============================================================

APP_VERSION = "1.0.1"

ENGINE_VERSION = 2

SCAN_INTERVAL = 30

CLOUD_RULE_REFRESH_SECONDS = (
    6 * 60 * 60
)

LEARNED_RULE_REFRESH_SECONDS = 60

REQUEST_TIMEOUT = 20

MAX_WORKERS = 80

MAX_NETWORK_ADDRESSES = 1024



# ============================================================
# SUPABASE
#
# USE ONLY THE PUBLISHABLE KEY.
# NEVER PUT A SECRET / SERVICE_ROLE KEY HERE.
# ============================================================

SUPABASE_URL = (
    "https://ephdcwogebxfsidytmrj.supabase.co"
)

SUPABASE_KEY = (
    "sb_publishable_L9TUAFyJ_S0l81UDNi8imw_FVTYm4cI"
)



# ============================================================
# UPDATE SOURCE
# ============================================================

GITHUB_LATEST_API = (
    "https://api.github.com/repos/"
    "developmentlab1-del/"
    "wifi-watch/releases/latest"
)

GITHUB_RELEASES_URL = (
    "https://github.com/"
    "developmentlab1-del/"
    "wifi-watch/releases/latest"
)



# ============================================================
# AGENT CAPABILITIES
# ============================================================

CAPABILITIES = {

    "arp":
        True,

    "icmp":
        True,

    "tcp_services":
        True,

    "mdns":
        True,

    "ssdp_upnp":
        True,

    "reverse_dns":
        True,

    "netbios":
        True,

    "mac_vendor":
        True,

    "http_identity":
        True,

    "tls_identity":
        True,

    "ssh_banner":
        True,

    "cloud_rules":
        True,

    "learned_fingerprints":
        True,

    "security_observation":
        True,

    "update_check":
        True,

}



# ============================================================
# TCP SERVICE MAP
# ============================================================

TCP_SERVICES = {

    21:
        "FTP",

    22:
        "SSH",

    23:
        "Telnet",

    53:
        "DNS",

    80:
        "HTTP",

    139:
        "NetBIOS",

    443:
        "HTTPS",

    445:
        "SMB",

    554:
        "RTSP",

    631:
        "IPP",

    1883:
        "MQTT",

    3389:
        "RDP",

    5000:
        "HTTP-alt",

    5001:
        "HTTPS-alt",

    5900:
        "VNC",

    7000:
        "AirPlay",

    8000:
        "HTTP-alt",

    8001:
        "HTTP-alt",

    8008:
        "Google Cast",

    8009:
        "Google Cast",

    8080:
        "HTTP-alt",

    8443:
        "HTTPS-alt",

    8883:
        "MQTT-TLS",

    9100:
        "RAW Printer",

    32400:
        "Plex",

    62078:
        "Apple Sync",

}


HTTP_PORTS = {

    80,

    5000,

    8000,

    8001,

    8008,

    8080,

    32400,

}


HTTPS_PORTS = {

    443,

    5001,

    8443,

}


REFUSED_CODES = {

    errno.ECONNREFUSED,

    61,

    111,

    10061,

}



# ============================================================
# MDNS / BONJOUR
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
# IDENTITY FILTERING
# ============================================================

BAD_VALUES = {

    "",

    "unknown",

    "none",

    "null",

    "nil",

    "device",

    "localhost",

    "local",

    "n/a",

    "na",

    "0,1,2",

    "0, 1, 2",

    "0.1.2",

    "default",

    "generic",

}


GENERIC_TITLES = {

    "login",

    "sign in",

    "home",

    "index",

    "welcome",

    "web interface",

    "management",

    "admin",

    "administrator",

    "dashboard",

    "router",

}


GENERIC_ANCHORS = {

    "iphone",

    "ipad",

    "android",

    "device",

    "router",

    "camera",

    "printer",

    "tv",

    "smart tv",

    "computer",

    "nas",

    "server",

}



# ============================================================
# STORAGE
# ============================================================

def get_app_folder():

    system = (
        platform.system()
    )


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


APP_FOLDER = (
    get_app_folder()
)

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

CLOUD_RULES_FILE = (
    APP_FOLDER
    /
    "fingerprint_rules.json"
)

LEARNED_RULES_FILE = (
    APP_FOLDER
    /
    "learned_fingerprints.json"
)



# ============================================================
# LOGGING
# ============================================================

def log(
    message
):

    line = (

        f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
        f"{message}"

    )


    print(
        line
    )


    try:

        with open(

            LOG_FILE,

            "a",

            encoding="utf-8"

        ) as file:

            file.write(
                line
                +
                "\n"
            )


    except Exception:

        pass



# ============================================================
# JSON FILE HELPERS
# ============================================================

def load_json_file(
    path,
    fallback=None
):

    if fallback is None:

        fallback = {}


    if not path.exists():

        return fallback


    try:

        with open(

            path,

            "r",

            encoding="utf-8"

        ) as file:

            return json.load(
                file
            )


    except Exception:

        return fallback


def save_json_file(
    path,
    data
):

    with open(

        path,

        "w",

        encoding="utf-8"

    ) as file:

        json.dump(

            data,

            file,

            indent=2,

            ensure_ascii=False

        )


    if os.name != "nt":

        try:

            os.chmod(
                path,
                0o600
            )

        except Exception:

            pass



# ============================================================
# CONFIG
# ============================================================

def load_config():

    return load_json_file(
        CONFIG_FILE,
        {}
    )


def save_config(
    data
):

    save_json_file(
        CONFIG_FILE,
        data
    )


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

    response = requests.post(

        (
            f"{SUPABASE_URL}"
            f"/rest/v1/rpc/"
            f"{function_name}"
        ),

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

def claim_pairing_code(
    code
):

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

        "network_id",

    ):

        if key not in result:

            raise RuntimeError(
                "Invalid pairing response."
            )


    config = {

        "agent_id":
            result[
                "agent_id"
            ],

        "agent_secret":
            result[
                "agent_secret"
            ],

        "network_id":
            result[
                "network_id"
            ],

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

def heartbeat(
    config
):

    return rpc(

        "agent_heartbeat",

        {

            "p_agent_id":
                config[
                    "agent_id"
                ],

            "p_agent_secret":
                config[
                    "agent_secret"
                ],

            "p_version":
                APP_VERSION,

        }

    )



# ============================================================
# AGENT HEALTH REPORT
# ============================================================

def report_scan(

    config,

    ruleset_version,

    duration_ms,

    device_count,

    agent_ip,

    error=None

):

    try:

        rpc(

            "agent_report_scan",

            {

                "p_agent_id":
                    config[
                        "agent_id"
                    ],

                "p_agent_secret":
                    config[
                        "agent_secret"
                    ],

                "p_engine_version":
                    ENGINE_VERSION,

                "p_ruleset_version":
                    ruleset_version,

                "p_capabilities":
                    CAPABILITIES,

                "p_duration_ms":
                    int(
                        duration_ms
                    ),

                "p_device_count":
                    int(
                        device_count
                    ),

                "p_agent_ip":
                    agent_ip,

                "p_last_error":
                    (
                        str(
                            error
                        )
                        if error
                        else None
                    ),

            }

        )


    except Exception as exc:

        log(
            f"Scan report error: {exc}"
        )



# ============================================================
# CLOUD / LEARNED RULE CACHE
# ============================================================

_cloud_rules_memory = None

_cloud_rules_fetched_at = 0

_learned_rules_memory = None

_learned_rules_fetched_at = 0



# ============================================================
# CLOUD FINGERPRINT RULES
# ============================================================

def fetch_cloud_rules(
    force=False
):

    global _cloud_rules_memory
    global _cloud_rules_fetched_at


    now = (
        time.time()
    )


    if (

        not force

        and

        _cloud_rules_memory
        is not None

        and

        now
        -
        _cloud_rules_fetched_at
        <
        CLOUD_RULE_REFRESH_SECONDS

    ):

        return (
            _cloud_rules_memory
        )


    try:

        result = rpc(

            "get_fingerprint_rules",

            {

                "p_engine_version":
                    ENGINE_VERSION

            }

        )


        if not isinstance(
            result,
            dict
        ):

            raise RuntimeError(
                "Invalid cloud rules response."
            )


        cached = {

            "fetched_at":
                now,

            "ruleset_version":
                result.get(
                    "ruleset_version",
                    "unknown"
                ),

            "rules":
                result.get(
                    "rules",
                    []
                ),

        }


        save_json_file(

            CLOUD_RULES_FILE,

            cached

        )


        _cloud_rules_memory = (
            cached
        )


        _cloud_rules_fetched_at = (
            now
        )


        log(

            f"Cloud rules: "
            f"{len(cached['rules'])} rule(s), "
            f"ruleset "
            f"{cached['ruleset_version']}"

        )


        return cached


    except Exception as exc:

        log(
            f"Cloud rule fetch failed: {exc}"
        )


        cached = load_json_file(

            CLOUD_RULES_FILE,

            {

                "ruleset_version":
                    "built-in",

                "rules":
                    [],

            }

        )


        _cloud_rules_memory = (
            cached
        )


        _cloud_rules_fetched_at = (
            now
        )


        return cached



# ============================================================
# PERSONAL LEARNED FINGERPRINTS
# ============================================================

def fetch_learned_rules(
    config,
    force=False
):

    global _learned_rules_memory
    global _learned_rules_fetched_at


    now = (
        time.time()
    )


    if (

        not force

        and

        _learned_rules_memory
        is not None

        and

        _learned_rules_memory.get(
            "network_id"
        )
        ==
        config.get(
            "network_id"
        )

        and

        now
        -
        _learned_rules_fetched_at
        <
        LEARNED_RULE_REFRESH_SECONDS

    ):

        return (
            _learned_rules_memory
        )


    try:

        result = rpc(

            "get_agent_learned_fingerprints",

            {

                "p_agent_id":
                    config[
                        "agent_id"
                    ],

                "p_agent_secret":
                    config[
                        "agent_secret"
                    ],

            }

        )


        if not isinstance(
            result,
            dict
        ):

            raise RuntimeError(
                "Invalid learned fingerprint response."
            )


        cached = {

            "fetched_at":
                now,

            "network_id":
                result.get(
                    "network_id"
                ),

            "rules":
                result.get(
                    "rules",
                    []
                ),

        }


        save_json_file(

            LEARNED_RULES_FILE,

            cached

        )


        _learned_rules_memory = (
            cached
        )


        _learned_rules_fetched_at = (
            now
        )


        log(

            "Personal learned fingerprints: "
            f"{len(cached['rules'])}"

        )


        return cached


    except Exception as exc:

        log(
            f"Learned fingerprint fetch failed: {exc}"
        )


        cached = load_json_file(

            LEARNED_RULES_FILE,

            {

                "network_id":
                    None,

                "rules":
                    [],

            }

        )


        if (
            cached.get(
                "network_id"
            )
            !=
            config.get(
                "network_id"
            )
        ):

            cached = {

                "network_id":
                    config.get(
                        "network_id"
                    ),

                "rules":
                    [],

            }


        _learned_rules_memory = (
            cached
        )


        _learned_rules_fetched_at = (
            now
        )


        return cached



# ============================================================
# COMMAND HELPERS
# ============================================================

def command_path(
    name,
    candidates
):

    found = (
        shutil.which(
            name
        )
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

def normalize_mac(
    mac
):

    if not mac:

        return None


    text = (

        str(
            mac
        )

        .strip()

        .lower()

        .replace(
            "-",
            ":"
        )

    )


    parts = (
        text.split(
            ":"
        )
    )


    if len(parts) != 6:

        return None


    output = []


    try:

        for part in parts:

            if (
                not part
                or
                len(part) > 2
            ):

                return None


            output.append(

                f"{int(part, 16):02x}"

            )


    except Exception:

        return None


    return ":".join(
        output
    )


def valid_mac(
    mac
):

    mac = (
        normalize_mac(
            mac
        )
    )


    if (
        not mac
        or
        mac
        in (
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
        )
    ):

        return False


    try:

        first_byte = int(

            mac.split(":")[0],

            16

        )


        return not bool(
            first_byte & 1
        )


    except Exception:

        return False


def private_mac(
    mac
):

    mac = (
        normalize_mac(
            mac
        )
    )


    if not mac:

        return False


    try:

        return bool(

            int(
                mac.split(":")[0],
                16
            )

            &
            2

        )


    except Exception:

        return False



# ============================================================
# IDENTITY TEXT FILTERING
# ============================================================

def clean_identity_text(

    value,

    require_letters=False,

    allow_short=False

):

    if value is None:

        return None


    value = str(
        value
    )


    def replace_oct(
        match
    ):

        try:

            return chr(

                int(
                    match.group(1),
                    8
                )

            )

        except Exception:

            return (
                match.group(0)
            )


    value = re.sub(

        r"\\([0-7]{3})",

        replace_oct,

        value

    )


    value = (

        value

        .replace(
            "\x00",
            ""
        )

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


    value = re.sub(

        r"\s+",

        " ",

        value

    ).strip()


    if (
        not value
        or
        value.lower()
        in
        BAD_VALUES
        or
        len(value) > 160
    ):

        return None


    try:

        ipaddress.ip_address(
            value
        )

        return None

    except Exception:

        pass


    if re.fullmatch(

        r"[\d\s,._\-]+",

        value

    ):

        return None


    if (

        not allow_short

        and

        len(value) < 2

    ):

        return None


    if (

        require_letters

        and

        not any(
            character.isalpha()
            for character in value
        )

    ):

        return None


    return value


def valid_model(
    value
):

    value = (
        clean_identity_text(

            value,

            require_letters=True

        )
    )


    if not value:

        return None


    if re.fullmatch(

        r"[vV]?\d+"
        r"([.,]\d+)+",

        value

    ):

        return None


    return value


def useful_http_title(
    value
):

    value = (
        clean_identity_text(

            value,

            require_letters=True

        )
    )


    if not value:

        return None


    lower = (
        value
        .lower()
        .strip()
    )


    if (

        lower in
        GENERIC_TITLES

        or

        len(value) > 120

    ):

        return None


    return value



# ============================================================
# MAC VENDOR
# ============================================================

def mac_vendor(
    mac
):

    mac = (
        normalize_mac(
            mac
        )
    )


    if (

        not valid_mac(
            mac
        )

        or

        private_mac(
            mac
        )

        or

        not MAC_VENDOR_PARSER

    ):

        return None


    try:

        value = (

            MAC_VENDOR_PARSER
            .get_comment(
                mac
            )

            or

            MAC_VENDOR_PARSER
            .get_manuf(
                mac
            )

        )


        return clean_identity_text(

            value,

            require_letters=True

        )


    except Exception:

        return None



# ============================================================
# DEVICE RECORD
# ============================================================

def new_record(
    ip
):

    return {

        "ip":
            str(
                ip
            ),

        "mac":
            None,

        "gateway":
            False,

        "local_agent":
            False,

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

        "http":
            [],

        "tls":
            [],

        "ssh":
            [],

        "netbios":
            [],

        "reverse_dns":
            None,

        "cloud_rule":
            None,

        "cloud_result":
            {},

        "learned_rule":
            None,

        "learned_result":
            {},

        "learned_confidence":
            0,

    }


def ensure_record(

    records,

    network,

    ip

):

    try:

        address = (
            ipaddress.ip_address(
                str(
                    ip
                )
            )
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

        records[
            key
        ] = (
            new_record(
                key
            )
        )


    return records[
        key
    ]


def add_candidate(

    record,

    field,

    value,

    source,

    score,

    model=False

):

    if model:

        value = (
            valid_model(
                value
            )
        )


    else:

        value = (
            clean_identity_text(

                value,

                require_letters=True

            )
        )


    if not value:

        return


    for item in record[field]:

        if (
            item[
                "value"
            ].lower()
            ==
            value.lower()
        ):

            if (
                score
                >
                item[
                    "score"
                ]
            ):

                item[
                    "score"
                ] = int(
                    score
                )


                item[
                    "source"
                ] = source


            record[
                "identity_sources"
            ].add(
                source
            )


            return


    record[
        field
    ].append({

        "value":
            value,

        "source":
            source,

        "score":
            int(
                score
            ),

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

    values = (
        record.get(
            field,
            []
        )
    )


    if not values:

        return None


    return max(

        values,

        key=lambda item:
            item.get(
                "score",
                0
            )

    )[
        "value"
    ]



# ============================================================
# LOCAL NETWORK
# ============================================================

def local_ip_address():

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

                    ip = (
                        ipaddress.ip_address(
                            address.address
                        )
                    )


                    if (

                        ip.is_private

                        and

                        not ip.is_loopback

                    ):

                        return str(
                            ip
                        )


                except Exception:

                    pass


    raise RuntimeError(
        "Unable to determine local IPv4 address."
    )


def network_details():

    local_ip = (
        local_ip_address()
    )


    interface = None

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

                interface = name

                netmask = (
                    address.netmask
                )

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


    if (
        network.num_addresses
        >
        MAX_NETWORK_ADDRESSES
    ):

        network = (
            ipaddress.ip_network(

                f"{local_ip}/24",

                strict=False

            )
        )


    return {

        "local_ip":
            local_ip,

        "interface":
            interface,

        "network":
            network,

        "own_mac":
            own_mac,

    }



# ============================================================
# DEFAULT GATEWAY
# ============================================================

def default_gateway():

    system = (
        platform.system()
    )


    try:

        if system == "Darwin":

            route = command_path(

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

                return (
                    match.group(1)
                )


        elif system == "Linux":

            ip_command = command_path(

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

                return (
                    match.group(1)
                )


        elif system == "Windows":

            flags = getattr(

                subprocess,

                "CREATE_NO_WINDOW",

                0

            )


            output = subprocess.check_output(

                [
                    "route",
                    "print",
                    "-4"
                ],

                text=True,

                errors="ignore",

                stderr=subprocess.DEVNULL,

                creationflags=flags

            )


            match = re.search(

                r"^\s*0\.0\.0\.0"
                r"\s+0\.0\.0\.0"
                r"\s+(\d+\.\d+\.\d+\.\d+)",

                output,

                re.MULTILINE

            )


            if match:

                return (
                    match.group(1)
                )


    except Exception:

        pass


    return None



# ============================================================
# NEIGHBOR SEED
# ============================================================

def seed_neighbor(
    ip
):

    sock = socket.socket(

        socket.AF_INET,

        socket.SOCK_DGRAM

    )


    sock.settimeout(
        0.12
    )


    try:

        sock.sendto(

            b"\x00",

            (
                str(
                    ip
                ),
                9
            )

        )


    except Exception:

        pass


    finally:

        sock.close()



# ============================================================
# ICMP
# ============================================================

def ping_host(
    ip
):

    ip = str(
        ip
    )


    system = (
        platform.system()
    )


    flags = 0


    if system == "Darwin":

        command = [

            command_path(

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


        flags = getattr(

            subprocess,

            "CREATE_NO_WINDOW",

            0

        )


    else:

        command = [

            command_path(

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


        if (
            result.returncode
            ==
            0
        ):

            return ip


    except Exception:

        pass


    return None



# ============================================================
# TCP DISCOVERY
# ============================================================

def tcp_probe(
    ip
):

    ip = str(
        ip
    )


    alive = False

    ports = []


    for port in TCP_SERVICES:

        sock = socket.socket(

            socket.AF_INET,

            socket.SOCK_STREAM

        )


        sock.settimeout(
            0.16
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

                ports.append(
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
        ports
    )



# ============================================================
# NEIGHBOR TABLE
# ============================================================

def macos_neighbors():

    arp = command_path(

        "arp",

        [
            "/usr/sbin/arp",
            "/sbin/arp"
        ]

    )


    output = subprocess.check_output(

        [
            arp,
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

        mac = (
            normalize_mac(
                raw_mac
            )
        )


        if valid_mac(
            mac
        ):

            result[
                ip
            ] = mac


    return result


def windows_neighbors():

    flags = getattr(

        subprocess,

        "CREATE_NO_WINDOW",

        0

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

        mac = (
            normalize_mac(
                raw_mac
            )
        )


        if valid_mac(
            mac
        ):

            result[
                ip
            ] = mac


    return result


def linux_neighbors():

    result = {}


    ip_command = command_path(

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
                ip_command,
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

            mac = (
                normalize_mac(
                    raw_mac
                )
            )


            if valid_mac(
                mac
            ):

                result[
                    ip
                ] = mac


    except Exception:

        pass


    return result


def neighbor_table():

    try:

        system = (
            platform.system()
        )


        if system == "Darwin":

            return (
                macos_neighbors()
            )


        if system == "Windows":

            return (
                windows_neighbors()
            )


        return (
            linux_neighbors()
        )


    except Exception as exc:

        log(
            f"Neighbor table error: {exc}"
        )


        return {}



# ============================================================
# REVERSE DNS
# ============================================================

def reverse_dns(
    ip
):

    try:

        hostname = (
            clean_identity_text(

                socket.gethostbyaddr(
                    ip
                )[0],

                require_letters=True

            )
        )


        return (
            ip,
            hostname
        )


    except Exception:

        return (
            ip,
            None
        )



# ============================================================
# NETBIOS
# ============================================================

def netbios_encoded_name():

    raw = (
        b"*"
        +
        b"\x00" * 15
    )


    encoded = bytearray()


    for value in raw:

        encoded.append(

            ord("A")
            +
            (
                (
                    value >> 4
                )
                &
                0x0F
            )

        )


        encoded.append(

            ord("A")
            +
            (
                value
                &
                0x0F
            )

        )


    return (

        b"\x20"
        +
        bytes(
            encoded
        )
        +
        b"\x00"

    )


def netbios_names(
    ip
):

    transaction_id = (

        int(
            time.time()
            *
            1000
        )

        &
        0xFFFF

    )


    packet = (

        struct.pack(

            "!HHHHHH",

            transaction_id,

            0x0000,

            1,

            0,

            0,

            0

        )

        +

        netbios_encoded_name()

        +

        struct.pack(

            "!HH",

            0x0021,

            0x0001

        )

    )


    sock = socket.socket(

        socket.AF_INET,

        socket.SOCK_DGRAM

    )


    sock.settimeout(
        0.45
    )


    try:

        sock.sendto(

            packet,

            (
                ip,
                137
            )

        )


        data, _ = (
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
            offset
            <
            len(data)
        ):

            length = (
                data[
                    offset
                ]
            )


            offset += 1


            if length == 0:

                break


            offset += length


        offset += 4


        if (
            data[
                offset
            ]
            &
            0xC0
        ) == 0xC0:

            offset += 2


        else:

            while True:

                length = (
                    data[
                        offset
                    ]
                )


                offset += 1


                if length == 0:

                    break


                offset += length


        (
            _record_type,
            _record_class,
            _ttl,
            rdlength

        ) = struct.unpack(

            "!HHIH",

            data[
                offset:
                offset + 10
            ]

        )


        offset += 10


        payload = data[

            offset:
            offset + rdlength

        ]


        if not payload:

            return []


        count = (
            payload[0]
        )


        position = 1

        names = []


        for _ in range(
            count
        ):

            entry = payload[

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


            suffix = (
                entry[15]
            )


            flags = struct.unpack(

                "!H",

                entry[16:18]

            )[0]


            group_name = bool(
                flags
                &
                0x8000
            )


            name = (
                clean_identity_text(

                    raw_name,

                    require_letters=True

                )
            )


            if (

                name

                and

                not group_name

                and

                suffix
                in (
                    0x00,
                    0x20
                )

                and

                name not in names

            ):

                names.append(
                    name
                )


            position += 18


        return names


    except Exception:

        return []



# ============================================================
# SSDP
# ============================================================

def parse_ssdp_headers(
    data
):

    try:

        text = (
            data.decode(
                "utf-8",
                errors="ignore"
            )
        )


    except Exception:

        return {}


    headers = {}


    for line in (
        text.splitlines()[1:]
    ):

        if ":" not in line:

            continue


        key, value = (
            line.split(
                ":",
                1
            )
        )


        headers[
            key.strip().lower()
        ] = value.strip()


    return headers


def ssdp_discovery():

    results = []


    packet = (

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

                    packet,

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
            3.0
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



# ============================================================
# UPNP
# ============================================================

def allowed_upnp_location(

    url,

    network

):

    try:

        parsed = (
            urllib.parse.urlparse(
                url
            )
        )


        if (

            parsed.scheme
            not in (
                "http",
                "https",
            )

            or

            not parsed.hostname

        ):

            return False


        try:

            address = (
                ipaddress.ip_address(
                    parsed.hostname
                )
            )


        except Exception:

            address = (
                ipaddress.ip_address(

                    socket.gethostbyname(
                        parsed.hostname
                    )

                )
            )


        return (

            address.version
            ==
            4

            and

            address
            in
            network

        )


    except Exception:

        return False


def xml_value(
    root,
    name
):

    name = (
        name.lower()
    )


    for element in root.iter():

        local_name = (

            element.tag

            .split("}")[-1]

            .lower()

        )


        if (

            local_name
            ==
            name

            and

            element.text

        ):

            value = (
                element.text
                .strip()
            )


            if value:

                return value


    return None


def upnp_identity(

    location,

    network

):

    if not allowed_upnp_location(

        location,

        network

    ):

        return None


    try:

        session = (
            requests.Session()
        )


        session.trust_env = False


        response = session.get(

            location,

            timeout=(
                0.8,
                1.7
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


        root = ET.fromstring(

            response.content[
                :524288
            ]

        )


        friendly = (
            clean_identity_text(

                xml_value(
                    root,
                    "friendlyName"
                ),

                require_letters=True

            )
        )


        manufacturer = (
            clean_identity_text(

                xml_value(
                    root,
                    "manufacturer"
                ),

                require_letters=True

            )
        )


        model_name = (
            valid_model(

                xml_value(
                    root,
                    "modelName"
                )

            )
        )


        model_number = (
            valid_model(

                xml_value(
                    root,
                    "modelNumber"
                )

            )
        )


        model = (
            model_name
            or
            model_number
        )


        if (

            model_name

            and

            model_number

            and

            model_number.lower()
            not in
            model_name.lower()

        ):

            model = (

                model_name
                +
                " "
                +
                model_number

            )


        return {

            "friendly_name":
                friendly,

            "manufacturer":
                manufacturer,

            "model":
                model,

            "device_type":
                xml_value(
                    root,
                    "deviceType"
                ),

        }


    except Exception:

        return None



# ============================================================
# MDNS
# ============================================================

def decode_txt(
    properties
):

    result = {}


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

                else

                str(
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

                else

                str(
                    raw_value
                )

            )


            result[
                key.lower()
            ] = (
                value.strip()
            )


        except Exception:

            pass


    return result


class MDNSListener(
    ServiceListener
):

    def __init__(
        self,
        results
    ):

        self.results = (
            results
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

        self.read(

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

        self.read(

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


    def read(

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


            instance = (
                clean_identity_text(

                    name,

                    require_letters=True

                )
            )


            server = (
                clean_identity_text(

                    info.server,

                    require_letters=True

                )
            )


            properties = (
                decode_txt(
                    info.properties
                )
            )


            for ip in (
                info.parsed_addresses(
                    IPVersion.V4Only
                )
            ):

                data = {

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
                        data
                    )


        except Exception:

            pass


def mdns_discovery():

    results = {}

    browsers = []

    zeroconf = None


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

                browsers.append(

                    ServiceBrowser(

                        zeroconf,

                        service_type,

                        listener

                    )

                )


            except Exception:

                pass


        time.sleep(
            4.0
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
# APPLY MDNS
# ============================================================

def apply_mdns(

    record,

    entries

):

    record[
        "mdns"
    ] = entries[:30]


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


        props = (
            entry.get(
                "properties",
                {}
            )
        )


        if instance:

            score = (

                82

                if any(

                    value
                    in
                    service

                    for value in (

                        "_googlecast",

                        "_airplay",

                        "_ipp",

                        "_printer",

                        "_workstation",

                    )

                )

                else

                72

            )


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


        for key in (

            "fn",

            "friendlyname",

            "friendly_name",

            "name",

            "n",

        ):

            if props.get(
                key
            ):

                add_candidate(

                    record,

                    "friendly_candidates",

                    props[
                        key
                    ],

                    "mdns_txt",

                    90

                )


        for key in (

            "md",

            "model",

        ):

            if props.get(
                key
            ):

                add_candidate(

                    record,

                    "model_candidates",

                    props[
                        key
                    ],

                    "mdns_txt",

                    86,

                    model=True

                )


        for key in (

            "manufacturer",

            "vendor",

            "mf",

        ):

            if props.get(
                key
            ):

                add_candidate(

                    record,

                    "vendor_candidates",

                    props[
                        key
                    ],

                    "mdns_txt",

                    86

                )


        record[
            "identity_sources"
        ].add(
            "mdns"
        )



# ============================================================
# APPLY SSDP
# ============================================================

def apply_ssdp(

    record,

    entries,

    network

):

    saved = []

    used_locations = set()


    for entry in entries:

        headers = (
            entry.get(
                "headers",
                {}
            )
        )


        location = (
            headers.get(
                "location"
            )
        )


        data = {

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

        }


        if (

            location

            and

            location
            not in
            used_locations

        ):

            used_locations.add(
                location
            )


            identity = (
                upnp_identity(

                    location,

                    network

                )
            )


            if identity:

                data[
                    "upnp_identity"
                ] = identity


                if identity.get(
                    "friendly_name"
                ):

                    add_candidate(

                        record,

                        "friendly_candidates",

                        identity[
                            "friendly_name"
                        ],

                        "ssdp_upnp",

                        96

                    )


                if identity.get(
                    "manufacturer"
                ):

                    add_candidate(

                        record,

                        "vendor_candidates",

                        identity[
                            "manufacturer"
                        ],

                        "ssdp_upnp",

                        97

                    )


                if identity.get(
                    "model"
                ):

                    add_candidate(

                        record,

                        "model_candidates",

                        identity[
                            "model"
                        ],

                        "ssdp_upnp",

                        97,

                        model=True

                    )


                record[
                    "identity_sources"
                ].add(
                    "ssdp_upnp"
                )


        saved.append(
            data
        )


    record[
        "ssdp"
    ] = saved[:25]



# ============================================================
# HTTP IDENTITY
# ============================================================

def extract_html_title(
    text
):

    if not text:

        return None


    match = re.search(

        r"<title[^>]*>(.*?)</title>",

        text,

        flags=(
            re.IGNORECASE
            |
            re.DOTALL
        )

    )


    if not match:

        return None


    title = re.sub(

        r"<[^>]+>",

        " ",

        match.group(1)

    )


    title = re.sub(

        r"\s+",

        " ",

        title

    ).strip()


    return (
        useful_http_title(
            title
        )
    )


def probe_http(

    ip,

    port,

    use_https=False

):

    scheme = (

        "https"

        if use_https

        else

        "http"

    )


    url = (

        f"{scheme}://"
        f"{ip}:"
        f"{port}/"

    )


    session = (
        requests.Session()
    )


    session.trust_env = False


    response = None


    try:

        response = session.get(

            url,

            timeout=(
                0.7,
                1.4
            ),

            allow_redirects=False,

            verify=False,

            stream=True,

            headers={

                "User-Agent":
                    f"WiFiWatch/{APP_VERSION}",

                "Accept":
                    (
                        "text/html,"
                        "application/xhtml+xml,"
                        "*/*;q=0.5"
                    ),

            }

        )


        body = bytearray()


        try:

            for chunk in (
                response.iter_content(
                    chunk_size=4096
                )
            ):

                if not chunk:

                    continue


                body.extend(
                    chunk
                )


                if len(body) >= 65536:

                    break


        except Exception:

            pass


        encoding = (

            response.encoding

            or

            "utf-8"

        )


        try:

            text = bytes(
                body
            ).decode(

                encoding,

                errors="ignore"

            )


        except Exception:

            text = bytes(
                body
            ).decode(

                "utf-8",

                errors="ignore"

            )


        return {

            "port":
                port,

            "scheme":
                scheme,

            "status":
                response.status_code,

            "server":
                clean_identity_text(

                    response.headers.get(
                        "Server"
                    ),

                    require_letters=True,

                    allow_short=True

                ),

            "title":
                extract_html_title(
                    text
                ),

            "content_type":
                response.headers.get(
                    "Content-Type"
                ),

            "location":
                response.headers.get(
                    "Location"
                ),

        }


    except Exception:

        return None


    finally:

        if response is not None:

            try:

                response.close()

            except Exception:

                pass


        session.close()



# ============================================================
# TLS CERTIFICATE IDENTITY
# ============================================================

def decode_certificate_der(
    der_bytes
):

    decoder = getattr(

        getattr(
            ssl,
            "_ssl",
            None
        ),

        "_test_decode_cert",

        None

    )


    if not decoder:

        return None


    temp_path = None


    try:

        pem = (
            ssl.DER_cert_to_PEM_cert(
                der_bytes
            )
        )


        with tempfile.NamedTemporaryFile(

            "w",

            delete=False,

            suffix=".pem",

            encoding="utf-8"

        ) as file:

            file.write(
                pem
            )


            temp_path = (
                file.name
            )


        return decoder(
            temp_path
        )


    except Exception:

        return None


    finally:

        if temp_path:

            try:

                os.unlink(
                    temp_path
                )

            except Exception:

                pass


def certificate_names(
    cert
):

    if not isinstance(
        cert,
        dict
    ):

        return (
            [],
            None
        )


    names = []


    for item in (
        cert.get(
            "subject",
            []
        )
    ):

        for (
            key,
            value
        ) in item:

            if key == "commonName":

                common_name = (
                    clean_identity_text(

                        value,

                        require_letters=True

                    )
                )


                if (

                    common_name

                    and

                    common_name
                    not in names

                ):

                    names.append(
                        common_name
                    )


    for (
        kind,
        value
    ) in (
        cert.get(
            "subjectAltName",
            []
        )
    ):

        if kind == "DNS":

            name = (
                clean_identity_text(

                    value,

                    require_letters=True

                )
            )


            if (

                name

                and

                name not in names

            ):

                names.append(
                    name
                )


    issuer_parts = []


    for item in (
        cert.get(
            "issuer",
            []
        )
    ):

        for (
            key,
            value
        ) in item:

            if key in (

                "commonName",

                "organizationName",

            ):

                cleaned = (
                    clean_identity_text(

                        value,

                        require_letters=True,

                        allow_short=True

                    )
                )


                if cleaned:

                    issuer_parts.append(
                        cleaned
                    )


    issuer = None


    if issuer_parts:

        issuer = " / ".join(

            dict.fromkeys(
                issuer_parts
            )

        )


    return (
        names[:10],
        issuer
    )


def probe_tls_certificate(

    ip,

    port

):

    context = (
        ssl.create_default_context()
    )


    context.check_hostname = False

    context.verify_mode = (
        ssl.CERT_NONE
    )


    raw = None

    wrapped = None


    try:

        raw = (
            socket.create_connection(

                (
                    ip,
                    port
                ),

                timeout=0.9

            )
        )


        wrapped = (
            context.wrap_socket(
                raw
            )
        )


        wrapped.settimeout(
            0.9
        )


        der = (
            wrapped.getpeercert(
                binary_form=True
            )
        )


        if not der:

            return None


        cert = (
            decode_certificate_der(
                der
            )
        )


        names, issuer = (
            certificate_names(
                cert
            )
        )


        return {

            "port":
                port,

            "names":
                names,

            "issuer":
                issuer,

        }


    except Exception:

        return None


    finally:

        try:

            if wrapped:

                wrapped.close()


            elif raw:

                raw.close()


        except Exception:

            pass



# ============================================================
# SSH BANNER
# ============================================================

def probe_ssh_banner(

    ip,

    port=22

):

    sock = socket.socket(

        socket.AF_INET,

        socket.SOCK_STREAM

    )


    sock.settimeout(
        0.8
    )


    try:

        sock.connect(
            (
                ip,
                port
            )
        )


        data = (
            sock.recv(
                512
            )
        )


        if not data:

            return None


        banner = (
            data.decode(

                "utf-8",

                errors="ignore"

            )
            .strip()
        )


        if not banner.startswith(
            "SSH-"
        ):

            return None


        return {

            "port":
                port,

            "banner":
                banner[:240],

        }


    except Exception:

        return None


    finally:

        try:

            sock.close()

        except Exception:

            pass



# ============================================================
# SERVICE METADATA ENRICHMENT
# ============================================================

def service_metadata_probe(

    ip,

    ports

):

    result = {

        "ip":
            ip,

        "http":
            [],

        "tls":
            [],

        "ssh":
            [],

    }


    for port in sorted(

        set(
            ports
        )
        &
        HTTP_PORTS

    ):

        item = (
            probe_http(

                ip,

                port,

                use_https=False

            )
        )


        if item:

            result[
                "http"
            ].append(
                item
            )


    for port in sorted(

        set(
            ports
        )
        &
        HTTPS_PORTS

    ):

        item = (
            probe_http(

                ip,

                port,

                use_https=True

            )
        )


        if item:

            result[
                "http"
            ].append(
                item
            )


        cert = (
            probe_tls_certificate(

                ip,

                port

            )
        )


        if cert:

            result[
                "tls"
            ].append(
                cert
            )


    if 22 in ports:

        item = (
            probe_ssh_banner(

                ip,

                22

            )
        )


        if item:

            result[
                "ssh"
            ].append(
                item
            )


    return result


def apply_service_metadata(

    record,

    metadata

):

    record[
        "http"
    ] = (
        metadata.get(
            "http",
            []
        )[:12]
    )


    record[
        "tls"
    ] = (
        metadata.get(
            "tls",
            []
        )[:8]
    )


    record[
        "ssh"
    ] = (
        metadata.get(
            "ssh",
            []
        )[:4]
    )


    for item in (
        record[
            "http"
        ]
    ):

        if item.get(
            "title"
        ):

            add_candidate(

                record,

                "friendly_candidates",

                item[
                    "title"
                ],

                "http_title",

                72

            )


            record[
                "identity_sources"
            ].add(
                "http"
            )


        if item.get(
            "server"
        ):

            record[
                "identity_sources"
            ].add(
                "http"
            )


    for item in (
        record[
            "tls"
        ]
    ):

        for name in (
            item.get(
                "names",
                []
            )
        ):

            add_candidate(

                record,

                "hostname_candidates",

                name,

                "tls_certificate",

                70

            )


        record[
            "identity_sources"
        ].add(
            "tls"
        )


    if record[
        "ssh"
    ]:

        record[
            "identity_sources"
        ].add(
            "ssh"
        )



# ============================================================
# RULE ENGINE TEXT
# ============================================================

def record_text(
    record
):

    values = []


    for field in (

        "friendly_candidates",

        "hostname_candidates",

        "vendor_candidates",

        "model_candidates",

    ):

        for item in (
            record.get(
                field,
                []
            )
        ):

            values.append(
                item.get(
                    "value",
                    ""
                )
            )


    for field in (

        "mdns",

        "ssdp",

        "http",

        "tls",

        "ssh",

        "netbios",

    ):

        values.append(

            json.dumps(

                record.get(
                    field,
                    []
                ),

                ensure_ascii=False

            )

        )


    return (

        " ".join(
            values
        )
        .lower()

    )


def text_has_any(

    text,

    values

):

    return any(

        str(
            value
        ).lower()
        in
        text

        for value in values

    )


def text_has_all(

    text,

    values

):

    return all(

        str(
            value
        ).lower()
        in
        text

        for value in values

    )



# ============================================================
# CLOUD RULE MATCHING
# ============================================================

def rule_matches(

    record,

    rule,

    ignore_device_id=True

):

    match = (
        rule.get(
            "match",
            {}
        )
        or
        {}
    )


    if not match:

        return False


    text = (
        record_text(
            record
        )
    )


    friendly = (

        best_candidate(

            record,

            "friendly_candidates"

        )

        or

        ""

    ).lower()


    hostname = (

        best_candidate(

            record,

            "hostname_candidates"

        )

        or

        ""

    ).lower()


    vendor = (

        best_candidate(

            record,

            "vendor_candidates"

        )

        or

        ""

    ).lower()


    model = (

        best_candidate(

            record,

            "model_candidates"

        )

        or

        ""

    ).lower()


    mdns_text = (
        json.dumps(

            record.get(
                "mdns",
                []
            ),

            ensure_ascii=False

        )
        .lower()
    )


    ssdp_text = (
        json.dumps(

            record.get(
                "ssdp",
                []
            ),

            ensure_ascii=False

        )
        .lower()
    )


    http_text = (
        json.dumps(

            record.get(
                "http",
                []
            ),

            ensure_ascii=False

        )
        .lower()
    )


    tls_text = (
        json.dumps(

            record.get(
                "tls",
                []
            ),

            ensure_ascii=False

        )
        .lower()
    )


    ssh_text = (
        json.dumps(

            record.get(
                "ssh",
                []
            ),

            ensure_ascii=False

        )
        .lower()
    )


    ports = set(

        record.get(
            "open_ports",
            set()
        )

    )


    record_mac = (
        normalize_mac(

            record.get(
                "mac"
            )

        )
    )


    for (
        key,
        raw_value
    ) in match.items():

        if (
            key
            ==
            "device_id"

            and

            ignore_device_id
        ):

            continue


        value = (

            raw_value

            if isinstance(
                raw_value,
                list
            )

            else

            [
                raw_value
            ]

        )


        if key == "contains_any":

            if not text_has_any(
                text,
                value
            ):

                return False


        elif key == "contains_all":

            if not text_has_all(
                text,
                value
            ):

                return False


        elif key in (

            "name_contains",

            "name_contains_any",

        ):

            if not text_has_any(

                (
                    friendly
                    +
                    " "
                    +
                    hostname
                ),

                value

            ):

                return False


        elif key == "hostname_contains_any":

            if not text_has_any(
                hostname,
                value
            ):

                return False


        elif key == "manufacturer_contains":

            if not text_has_any(
                vendor,
                value
            ):

                return False


        elif key == "model_contains":

            if not text_has_any(
                model,
                value
            ):

                return False


        elif key == "mdns_contains":

            if not text_has_any(
                mdns_text,
                value
            ):

                return False


        elif key == "ssdp_contains":

            if not text_has_any(
                ssdp_text,
                value
            ):

                return False


        elif key == "http_contains":

            if not text_has_any(
                http_text,
                value
            ):

                return False


        elif key == "tls_contains":

            if not text_has_any(
                tls_text,
                value
            ):

                return False


        elif key == "ssh_contains":

            if not text_has_any(
                ssh_text,
                value
            ):

                return False


        elif key == "ports_any":

            wanted = {

                int(
                    item
                )

                for item in value

            }


            if not (
                ports
                &
                wanted
            ):

                return False


        elif key == "ports_all":

            wanted = {

                int(
                    item
                )

                for item in value

            }


            if not wanted.issubset(
                ports
            ):

                return False


        elif key == "mac_exact":

            wanted = {

                normalize_mac(
                    item
                )

                for item in value

            }


            if (

                not record_mac

                or

                record_mac
                not in
                wanted

            ):

                return False


        elif key == "mac_prefix":

            prefixes = [

                str(
                    item
                )
                .lower()
                .replace(
                    "-",
                    ":"
                )

                for item in value

            ]


            if (

                not record_mac

                or

                not any(

                    record_mac.startswith(
                        prefix
                    )

                    for prefix in prefixes

                )

            ):

                return False


        elif key == "gateway":

            if (
                bool(
                    record.get(
                        "gateway"
                    )
                )
                !=
                bool(
                    raw_value
                )
            ):

                return False


        elif key == "private_mac":

            if (

                bool(

                    record_mac

                    and

                    private_mac(
                        record_mac
                    )

                )

                !=

                bool(
                    raw_value
                )

            ):

                return False


        else:

            return False


    return True



# ============================================================
# PERSONAL LEARNING
# ============================================================

def specific_anchor(
    values
):

    if not isinstance(
        values,
        list
    ):

        values = [
            values
        ]


    for value in values:

        text = (

            str(
                value
            )
            .strip()
            .lower()

        )


        if (

            len(text) >= 5

            and

            text not in
            GENERIC_ANCHORS

        ):

            return True


    return False


def learned_rule_match_strength(

    record,

    rule

):

    """
    Personal learned identity matcher.

    A stable globally-administered MAC can identify a device by itself.

    If there is no stable MAC, the Agent requires useful hostname/model
    or several independent service fingerprints.

    IP address is intentionally never used as identity proof.
    """

    match = (
        rule.get(
            "match",
            {}
        )
        or
        {}
    )


    record_mac = (
        normalize_mac(

            record.get(
                "mac"
            )

        )
    )


    # --------------------------------------------------------
    # STRONGEST ANCHOR: STABLE MAC
    # --------------------------------------------------------

    if match.get(
        "mac_exact"
    ):

        wanted = (
            match.get(
                "mac_exact"
            )
        )


        wanted = (

            wanted

            if isinstance(
                wanted,
                list
            )

            else

            [
                wanted
            ]

        )


        wanted = {

            normalize_mac(
                item
            )

            for item in wanted

        }


        if (

            record_mac

            and

            not private_mac(
                record_mac
            )

            and

            record_mac in wanted

        ):

            return 99


        return 0


    hostname = (

        best_candidate(

            record,

            "hostname_candidates"

        )

        or

        ""

    ).lower()


    vendor = (

        best_candidate(

            record,

            "vendor_candidates"

        )

        or

        ""

    ).lower()


    model = (

        best_candidate(

            record,

            "model_candidates"

        )

        or

        ""

    ).lower()


    mdns_text = (
        json.dumps(

            record.get(
                "mdns",
                []
            ),

            ensure_ascii=False

        )
        .lower()
    )


    ssdp_text = (
        json.dumps(

            record.get(
                "ssdp",
                []
            ),

            ensure_ascii=False

        )
        .lower()
    )


    http_text = (
        json.dumps(

            record.get(
                "http",
                []
            ),

            ensure_ascii=False

        )
        .lower()
    )


    tls_text = (
        json.dumps(

            record.get(
                "tls",
                []
            ),

            ensure_ascii=False

        )
        .lower()
    )


    score = 0

    strong_anchor = False


    values = (
        match.get(
            "hostname_contains_any"
        )
    )


    if (

        values

        and

        specific_anchor(
            values
        )

    ):

        values = (

            values

            if isinstance(
                values,
                list
            )

            else

            [
                values
            ]

        )


        if text_has_any(
            hostname,
            values
        ):

            score += 3

            strong_anchor = True


    values = (
        match.get(
            "model_contains"
        )
    )


    if (

        values

        and

        specific_anchor(
            values
        )

    ):

        values = (

            values

            if isinstance(
                values,
                list
            )

            else

            [
                values
            ]

        )


        if text_has_any(
            model,
            values
        ):

            score += 3

            strong_anchor = True


    values = (
        match.get(
            "ssdp_contains"
        )
    )


    if (

        values

        and

        specific_anchor(
            values
        )

    ):

        values = (

            values

            if isinstance(
                values,
                list
            )

            else

            [
                values
            ]

        )


        if text_has_any(
            ssdp_text,
            values
        ):

            score += 2


    values = (
        match.get(
            "tls_contains"
        )
    )


    if (

        values

        and

        specific_anchor(
            values
        )

    ):

        values = (

            values

            if isinstance(
                values,
                list
            )

            else

            [
                values
            ]

        )


        if text_has_any(
            tls_text,
            values
        ):

            score += 2


    values = (
        match.get(
            "http_contains"
        )
    )


    if (

        values

        and

        specific_anchor(
            values
        )

    ):

        values = (

            values

            if isinstance(
                values,
                list
            )

            else

            [
                values
            ]

        )


        if text_has_any(
            http_text,
            values
        ):

            score += 2


    values = (
        match.get(
            "mdns_contains"
        )
    )


    if values:

        values = (

            values

            if isinstance(
                values,
                list
            )

            else

            [
                values
            ]

        )


        if text_has_any(
            mdns_text,
            values
        ):

            score += 1


    values = (
        match.get(
            "manufacturer_contains"
        )
    )


    if values:

        values = (

            values

            if isinstance(
                values,
                list
            )

            else

            [
                values
            ]

        )


        if text_has_any(
            vendor,
            values
        ):

            score += 1


    if (

        strong_anchor

        and

        score >= 3

    ):

        if score >= 5:

            return 97


        return 94


    if score >= 5:

        return 95


    return 0


def apply_learned_rules(

    record,

    rules

):

    ordered = sorted(

        rules,

        key=lambda rule:
            int(
                rule.get(
                    "priority",
                    0
                )
            ),

        reverse=True

    )


    for rule in ordered:

        try:

            strength = (
                learned_rule_match_strength(

                    record,

                    rule

                )
            )


            if strength <= 0:

                continue


            record[
                "learned_rule"
            ] = (
                rule.get(
                    "name"
                )
            )


            record[
                "learned_result"
            ] = (
                rule.get(
                    "result",
                    {}
                )
                or
                {}
            )


            record[
                "learned_confidence"
            ] = strength


            record[
                "identity_sources"
            ].add(
                "learned_fingerprint"
            )


            return


        except Exception:

            continue



# ============================================================
# CLOUD RULES
# ============================================================

def apply_cloud_rules(

    record,

    rules

):

    ordered = sorted(

        rules,

        key=lambda rule:
            int(
                rule.get(
                    "priority",
                    0
                )
            ),

        reverse=True

    )


    for rule in ordered:

        try:

            if not rule_matches(

                record,

                rule,

                ignore_device_id=True

            ):

                continue


            record[
                "cloud_rule"
            ] = (
                rule.get(
                    "name"
                )
            )


            record[
                "cloud_result"
            ] = (
                rule.get(
                    "result",
                    {}
                )
                or
                {}
            )


            record[
                "identity_sources"
            ].add(
                "cloud_rule"
            )


            return


        except Exception:

            continue



# ============================================================
# DEVICE TYPE ENGINE
# ============================================================

def infer_device_type(

    record,

    friendly,

    hostname,

    vendor,

    model

):

    if record.get(
        "local_agent"
    ):

        return "computer"


    if record.get(
        "gateway"
    ):

        return "router_gateway"


    combined = (

        " ".join(

            value

            for value in (

                friendly,

                hostname,

                vendor,

                model,

            )

            if value

        )

        .lower()

    )


    evidence = (
        record_text(
            record
        )
    )


    ports = (
        record.get(
            "open_ports",
            set()
        )
    )


    # --------------------------------------------------------
    # COMPUTER
    # --------------------------------------------------------

    if any(

        value
        in
        combined

        for value in (

            "macbook",

            "imac",

            "mac mini",

            "mac-mini",

            "mac studio",

            "mac-studio",

            "desktop",

            "laptop",

            "thinkpad",

            "latitude",

            "elitebook",

            "surface pro",

        )

    ):

        return "computer"


    # --------------------------------------------------------
    # PHONE / TABLET
    # --------------------------------------------------------

    if any(

        value
        in
        combined

        for value in (

            "iphone",

            "ipad",

            "android",

            "galaxy",

            "pixel",

            "phone",

        )

    ):

        return "mobile"


    # --------------------------------------------------------
    # GAME CONSOLE
    # --------------------------------------------------------

    if any(

        value
        in
        combined

        for value in (

            "playstation",

            "ps5",

            "ps4",

            "xbox",

            "nintendo",

        )

    ):

        return "game_console"


    # --------------------------------------------------------
    # PRINTER
    # --------------------------------------------------------

    if (

        "_ipp._tcp"
        in
        evidence

        or

        "_printer._tcp"
        in
        evidence

        or

        631 in ports

        or

        9100 in ports

        or

        "printer"
        in
        combined

        or

        "laserjet"
        in
        combined

    ):

        return "printer"


    # --------------------------------------------------------
    # NAS
    # --------------------------------------------------------

    if any(

        value
        in
        combined

        for value in (

            "synology",

            "qnap",

            "diskstation",

            "nas",

        )

    ):

        return "nas"


    # --------------------------------------------------------
    # CAMERA
    # --------------------------------------------------------

    if any(

        value
        in
        combined

        for value in (

            "camera",

            "ipcam",

            "doorbell",

            "reolink",

            "hikvision",

            "dahua",

            "ring",

            "eufycam",

        )

    ):

        return "camera"


    # --------------------------------------------------------
    # SMART TV / MEDIA
    # --------------------------------------------------------

    if any(

        value
        in
        combined

        for value in (

            "mitv",

            "mi tv",

            "mi box",

            "mi stick",

            "chromecast",

            "google tv",

            "apple tv",

            "appletv",

            "roku",

            "bravia",

            "webos",

            "tizen",

            "television",

            "smart tv",

        )

    ):

        return "smart_tv_media"


    if (

        "mediarenderer"
        in
        evidence

        or

        "_googlecast._tcp"
        in
        evidence

    ):

        return "smart_tv_media"


    # --------------------------------------------------------
    # SMART HOME
    # --------------------------------------------------------

    if (
        "_hap._tcp"
        in
        evidence
    ):

        return "smart_home"


    # --------------------------------------------------------
    # MEDIA SERVER
    # --------------------------------------------------------

    if 32400 in ports:

        return "media_server"


    # --------------------------------------------------------
    # COMPUTER / NAS
    # --------------------------------------------------------

    if (

        445 in ports

        or

        139 in ports

        or

        3389 in ports

    ):

        return "computer_or_nas"


    # --------------------------------------------------------
    # COMPUTER / SERVER
    # --------------------------------------------------------

    if 22 in ports:

        return "computer_or_server"


    # --------------------------------------------------------
    # APPLE DEVICE
    # --------------------------------------------------------

    if 62078 in ports:

        return "apple_device"


    return "unknown"



# ============================================================
# OS ENGINE
# ============================================================

def infer_os(

    record,

    friendly,

    hostname,

    vendor,

    model,

    device_type

):

    if record.get(
        "local_agent"
    ):

        system = (
            platform.system()
        )


        if system == "Darwin":

            return "macOS"


        if system == "Windows":

            return "Windows"


        if system == "Linux":

            return "Linux"


    combined = (

        " ".join(

            value

            for value in (

                friendly,

                hostname,

                vendor,

                model,

            )

            if value

        )

        .lower()

    )


    ssh_text = (
        json.dumps(

            record.get(
                "ssh",
                []
            ),

            ensure_ascii=False

        )
        .lower()
    )


    if any(

        value
        in
        combined

        for value in (

            "macbook",

            "imac",

            "mac mini",

            "mac studio",

        )

    ):

        return "macOS"


    if "iphone" in combined:

        return "iOS"


    if "ipad" in combined:

        return "iPadOS"


    if any(

        value
        in
        combined

        for value in (

            "mitv",

            "mi tv",

            "google tv",

            "android",

            "galaxy",

            "pixel",

        )

    ):

        return "Android / Android TV"


    if 3389 in record.get(
        "open_ports",
        set()
    ):

        return "Windows-like"


    if "dropbear" in ssh_text:

        return "Embedded Linux-like"


    if (

        "openssh"
        in
        ssh_text

        and

        device_type
        in (
            "computer_or_server",
            "nas",
            "router_gateway",
        )

    ):

        return "Unix/Linux-like"


    if (
        device_type
        ==
        "apple_device"
    ):

        return "Apple OS"


    return None



# ============================================================
# SECURITY OBSERVATION
# ============================================================

def security_assessment(
    ports
):

    ports = set(
        ports
    )


    findings = []


    warning_map = {

        23: (

            "Telnet service reachable",

            (
                "Telnet is an unencrypted "
                "remote administration protocol."
            ),

        ),

        21: (

            "FTP service reachable",

            (
                "FTP can transfer credentials "
                "and data without encryption."
            ),

        ),

    }


    review_map = {

        80: (

            "HTTP service reachable",

            (
                "An unencrypted HTTP service "
                "is reachable on the LAN."
            ),

        ),

        445: (

            "SMB service reachable",

            (
                "File sharing is reachable "
                "from the local network."
            ),

        ),

        3389: (

            "Remote Desktop reachable",

            (
                "RDP is reachable from the "
                "local network."
            ),

        ),

        1883: (

            "MQTT service reachable",

            (
                "MQTT is available on its "
                "common non-TLS port."
            ),

        ),

        554: (

            "RTSP service reachable",

            (
                "A network media stream "
                "endpoint is reachable."
            ),

        ),

        5900: (

            "VNC service reachable",

            (
                "A VNC remote desktop "
                "service is reachable."
            ),

        ),

        9100: (

            "Raw printing reachable",

            (
                "Raw TCP printing is "
                "available on port 9100."
            ),

        ),

    }


    for (
        port,
        information
    ) in warning_map.items():

        if port in ports:

            findings.append({

                "severity":
                    "warning",

                "title":
                    information[0],

                "detail":
                    information[1],

                "port":
                    port,

            })


    for (
        port,
        information
    ) in review_map.items():

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


    levels = {

        item[
            "severity"
        ]

        for item in findings

    }


    if "warning" in levels:

        return (
            "warning",
            findings
        )


    if "review" in levels:

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
                        "The limited local-network service check "
                        "did not find one of WiFi Watch's currently "
                        "flagged services. This does not prove the "
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
                    "The device was discovered, but none of the "
                    "limited TCP services checked by WiFi Watch responded."
                ),

        }]

    )



# ============================================================
# IDENTITY CONFIDENCE
# ============================================================

def identity_confidence(

    record,

    friendly,

    hostname,

    vendor,

    model,

    device_type

):

    if record.get(
        "local_agent"
    ):

        return 99


    if record.get(
        "learned_rule"
    ):

        return max(

            90,

            min(

                99,

                int(
                    record.get(
                        "learned_confidence",
                        94
                    )
                )

            )

        )


    if record.get(
        "gateway"
    ):

        return 90


    scores = []


    for field in (

        "friendly_candidates",

        "hostname_candidates",

        "vendor_candidates",

        "model_candidates",

    ):

        for item in (
            record.get(
                field,
                []
            )
        ):

            scores.append(

                int(
                    item.get(
                        "score",
                        0
                    )
                )

            )


    base = (

        max(
            scores
        )

        if scores

        else

        15

    )


    if record.get(
        "cloud_rule"
    ):

        base = max(
            base,
            86
        )


    if (

        vendor

        and

        model

    ):

        base += 3


    if (

        friendly

        and

        hostname

    ):

        base += 2


    if (
        device_type
        !=
        "unknown"
    ):

        base += 2


    sources = len(

        record.get(
            "identity_sources",
            set()
        )

    )


    if sources >= 3:

        base += 2


    if sources >= 5:

        base += 1


    return max(

        0,

        min(
            99,
            base
        )

    )



# ============================================================
# SERVICE OUTPUT
# ============================================================

def service_output(
    ports
):

    return [

        {

            "protocol":
                "tcp",

            "port":
                int(
                    port
                ),

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
# FULL EXPERT SCAN
# ============================================================

def scan_network(

    config,

    force_rules=False

):

    started = (
        time.time()
    )


    details = (
        network_details()
    )


    network = (
        details[
            "network"
        ]
    )


    local_ip = (
        details[
            "local_ip"
        ]
    )


    own_mac = (
        details[
            "own_mac"
        ]
    )


    hosts = list(
        network.hosts()
    )


    records = {}


    cloud_package = (
        fetch_cloud_rules(
            force=force_rules
        )
    )


    learned_package = (
        fetch_learned_rules(

            config,

            force=force_rules

        )
    )


    ruleset_version = (
        cloud_package.get(
            "ruleset_version",
            "unknown"
        )
    )


    cloud_rules = (
        cloud_package.get(
            "rules",
            []
        )
    )


    learned_rules = (
        learned_package.get(
            "rules",
            []
        )
    )


    # ========================================================
    # LOCAL AGENT
    # ========================================================

    local_record = (
        ensure_record(

            records,

            network,

            local_ip

        )
    )


    local_record[
        "local_agent"
    ] = True


    local_record[
        "mac"
    ] = own_mac


    local_record[
        "methods"
    ].add(
        "agent"
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


    # ========================================================
    # GATEWAY
    # ========================================================

    gateway = (
        default_gateway()
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
        f"WiFi Watch Agent {APP_VERSION}"
    )

    log(
        f"Engine {ENGINE_VERSION}"
    )

    log(
        f"Ruleset {ruleset_version}"
    )

    log(
        f"Personal learned rules {len(learned_rules)}"
    )

    log(
        f"Network {network}"
    )

    log(
        f"Local IP {local_ip}"
    )

    log(
        f"Gateway {gateway}"
    )


    # ========================================================
    # PASS 1 - NEIGHBOR SEED
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
    # PASS 2 - ICMP
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


        for future in (
            concurrent.futures
            .as_completed(
                futures
            )
        ):

            try:

                ip = (
                    future.result()
                )


                if ip:

                    record = (
                        ensure_record(

                            records,

                            network,

                            ip

                        )
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
    # PASS 3 - TCP SERVICES
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
                    ports

                ) = future.result()


                if not alive:

                    continue


                record = (
                    ensure_record(

                        records,

                        network,

                        ip

                    )
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
                    ports
                )


            except Exception:

                pass


    # ========================================================
    # PASS 4 - SSDP / UPNP
    # ========================================================

    ssdp_by_ip = {}


    for entry in (
        ssdp_discovery()
    ):

        ip = (
            entry.get(
                "ip"
            )
        )


        record = (
            ensure_record(

                records,

                network,

                ip

            )
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
            entry
        )


    for (
        ip,
        entries
    ) in ssdp_by_ip.items():

        apply_ssdp(

            records[
                ip
            ],

            entries,

            network

        )


    # ========================================================
    # PASS 5 - MDNS
    # ========================================================

    for (
        ip,
        entries
    ) in (
        mdns_discovery()
        .items()
    ):

        record = (
            ensure_record(

                records,

                network,

                ip

            )
        )


        if not record:

            continue


        record[
            "methods"
        ].add(
            "mdns"
        )


        apply_mdns(

            record,

            entries

        )


    # ========================================================
    # PASS 6 - ARP
    # ========================================================

    time.sleep(
        1
    )


    for (
        ip,
        mac
    ) in (
        neighbor_table()
        .items()
    ):

        record = (
            ensure_record(

                records,

                network,

                ip

            )
        )


        if not record:

            continue


        record[
            "methods"
        ].add(
            "arp"
        )


        record[
            "mac"
        ] = mac


        vendor = (
            mac_vendor(
                mac
            )
        )


        if vendor:

            add_candidate(

                record,

                "vendor_candidates",

                vendor,

                "mac_oui",

                74

            )


    # ========================================================
    # PASS 7 - REVERSE DNS
    # ========================================================

    discovered_ips = list(
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

            for ip in discovered_ips

        ]


        for future in (
            concurrent.futures
            .as_completed(
                futures
            )
        ):

            try:

                ip, hostname = (
                    future.result()
                )


                if (

                    hostname

                    and

                    ip in records

                ):

                    records[
                        ip
                    ][
                        "reverse_dns"
                    ] = hostname


                    add_candidate(

                        records[
                            ip
                        ],

                        "hostname_candidates",

                        hostname,

                        "reverse_dns",

                        66

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

            for ip in list(
                records.keys()
            )

        }


        for future in (
            concurrent.futures
            .as_completed(
                futures
            )
        ):

            ip = (
                futures[
                    future
                ]
            )


            try:

                names = (
                    future.result()
                )


                records[
                    ip
                ][
                    "netbios"
                ] = names


                if names:

                    add_candidate(

                        records[
                            ip
                        ],

                        "friendly_candidates",

                        names[0],

                        "netbios",

                        86

                    )


                    add_candidate(

                        records[
                            ip
                        ],

                        "hostname_candidates",

                        names[0],

                        "netbios",

                        84

                    )


            except Exception:

                pass


    # ========================================================
    # SECOND TCP CHECK FOR LATE DISCOVERIES
    # ========================================================

    late_ips = [

        ip

        for (
            ip,
            record
        ) in records.items()

        if not record[
            "open_ports"
        ]

    ]


    with concurrent.futures.ThreadPoolExecutor(

        max_workers=
            MAX_WORKERS

    ) as executor:

        futures = [

            executor.submit(

                tcp_probe,

                ip

            )

            for ip in late_ips

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
                    ports

                ) = future.result()


                if (

                    alive

                    and

                    ip in records

                ):

                    records[
                        ip
                    ][
                        "methods"
                    ].add(
                        "tcp"
                    )


                    records[
                        ip
                    ][
                        "open_ports"
                    ].update(
                        ports
                    )


            except Exception:

                pass


    # ========================================================
    # PASS 9 - HTTP / TLS / SSH IDENTITY
    # ========================================================

    with concurrent.futures.ThreadPoolExecutor(

        max_workers=24

    ) as executor:

        futures = {

            executor.submit(

                service_metadata_probe,

                ip,

                record[
                    "open_ports"
                ]

            ):
            ip

            for (
                ip,
                record
            ) in records.items()

            if record[
                "open_ports"
            ]

        }


        for future in (
            concurrent.futures
            .as_completed(
                futures
            )
        ):

            ip = (
                futures[
                    future
                ]
            )


            try:

                metadata = (
                    future.result()
                )


                apply_service_metadata(

                    records[
                        ip
                    ],

                    metadata

                )


            except Exception:

                pass


    # ========================================================
    # PASS 10 - PERSONAL + CLOUD INTELLIGENCE
    # ========================================================

    for record in (
        records.values()
    ):

        apply_learned_rules(

            record,

            learned_rules

        )


        apply_cloud_rules(

            record,

            cloud_rules

        )


    # ========================================================
    # FINAL IDENTITY
    # ========================================================

    devices = []


    for ip in sorted(

        records.keys(),

        key=lambda value:
            ipaddress.ip_address(
                value
            )

    ):

        record = (
            records[
                ip
            ]
        )


        friendly = (
            best_candidate(

                record,

                "friendly_candidates"

            )
        )


        hostname = (
            best_candidate(

                record,

                "hostname_candidates"

            )
        )


        vendor = (
            best_candidate(

                record,

                "vendor_candidates"

            )
        )


        model = (
            best_candidate(

                record,

                "model_candidates"

            )
        )


        cloud_result = (
            record.get(
                "cloud_result",
                {}
            )
        )


        learned_result = (
            record.get(
                "learned_result",
                {}
            )
        )


        # ----------------------------------------------------
        # GLOBAL CLOUD IDENTITY
        # ----------------------------------------------------

        if cloud_result.get(
            "friendly_name"
        ):

            friendly = (

                clean_identity_text(

                    cloud_result[
                        "friendly_name"
                    ],

                    require_letters=True

                )

                or

                friendly

            )


        if cloud_result.get(
            "manufacturer"
        ):

            vendor = (

                clean_identity_text(

                    cloud_result[
                        "manufacturer"
                    ],

                    require_letters=True

                )

                or

                vendor

            )


        if cloud_result.get(
            "model"
        ):

            model = (

                valid_model(

                    cloud_result[
                        "model"
                    ]

                )

                or

                model

            )


        device_type = (
            infer_device_type(

                record,

                friendly,

                hostname,

                vendor,

                model

            )
        )


        os_guess = (
            infer_os(

                record,

                friendly,

                hostname,

                vendor,

                model,

                device_type

            )
        )


        if cloud_result.get(
            "device_type"
        ):

            device_type = str(

                cloud_result[
                    "device_type"
                ]

            )


        if cloud_result.get(
            "os_guess"
        ):

            os_guess = str(

                cloud_result[
                    "os_guess"
                ]

            )


        # ----------------------------------------------------
        # PERSONAL LEARNING OVERRIDES GLOBAL GENERIC RULES
        # ----------------------------------------------------

        if learned_result.get(
            "friendly_name"
        ):

            friendly = (

                clean_identity_text(

                    learned_result[
                        "friendly_name"
                    ],

                    require_letters=True

                )

                or

                friendly

            )


        if learned_result.get(
            "manufacturer"
        ):

            vendor = (

                clean_identity_text(

                    learned_result[
                        "manufacturer"
                    ],

                    require_letters=True

                )

                or

                vendor

            )


        if learned_result.get(
            "model"
        ):

            model = (

                valid_model(

                    learned_result[
                        "model"
                    ]

                )

                or

                model

            )


        if learned_result.get(
            "device_type"
        ):

            device_type = str(

                learned_result[
                    "device_type"
                ]

            )


        if learned_result.get(
            "os_guess"
        ):

            os_guess = str(

                learned_result[
                    "os_guess"
                ]

            )


        # ----------------------------------------------------
        # LOCAL AGENT ROLE IS AUTHORITATIVE
        # ----------------------------------------------------

        if record.get(
            "local_agent"
        ):

            device_type = (
                "computer"
            )


            system = (
                platform.system()
            )


            if system == "Darwin":

                os_guess = (
                    "macOS"
                )


                vendor = (

                    vendor

                    or

                    "Apple"

                )


            elif system == "Windows":

                os_guess = (
                    "Windows"
                )


            elif system == "Linux":

                os_guess = (
                    "Linux"
                )


        # ----------------------------------------------------
        # GATEWAY ROLE IS AUTHORITATIVE
        # ----------------------------------------------------

        if record.get(
            "gateway"
        ):

            device_type = (
                "router_gateway"
            )


        confidence = (
            identity_confidence(

                record,

                friendly,

                hostname,

                vendor,

                model,

                device_type

            )
        )


        (
            security_status,
            security_findings

        ) = (
            security_assessment(

                record[
                    "open_ports"
                ]

            )
        )


        mac = (
            normalize_mac(

                record.get(
                    "mac"
                )

            )
        )


        if not valid_mac(
            mac
        ):

            mac = None


        fingerprint_rule = (

            record.get(
                "learned_rule"
            )

            or

            record.get(
                "cloud_rule"
            )

        )


        fingerprint_data = {

            "engine_version":
                ENGINE_VERSION,

            "ruleset_version":
                ruleset_version,

            "fingerprint_rule":
                fingerprint_rule,

            "learned_rule":
                record.get(
                    "learned_rule"
                ),

            "cloud_rule":
                record.get(
                    "cloud_rule"
                ),

            "gateway":
                bool(
                    record.get(
                        "gateway"
                    )
                ),

            "local_agent":
                bool(
                    record.get(
                        "local_agent"
                    )
                ),

            "private_mac":
                bool(

                    mac

                    and

                    private_mac(
                        mac
                    )

                ),

            "reverse_dns":
                record.get(
                    "reverse_dns"
                ),

            "netbios_names":
                record.get(
                    "netbios",
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

            "http_identity":
                record.get(
                    "http",
                    []
                ),

            "tls_identity":
                record.get(
                    "tls",
                    []
                ),

            "ssh_banners":
                record.get(
                    "ssh",
                    []
                ),

            "name_candidates":
                record.get(
                    "friendly_candidates",
                    []
                )[:12],

            "hostname_candidates":
                record.get(
                    "hostname_candidates",
                    []
                )[:12],

            "manufacturer_candidates":
                record.get(
                    "vendor_candidates",
                    []
                )[:12],

            "model_candidates":
                record.get(
                    "model_candidates",
                    []
                )[:12],

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

            "fingerprint_rule":
                fingerprint_rule,

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
                service_output(

                    record[
                        "open_ports"
                    ]

                ),

            "security_status":
                security_status,

            "security_findings":
                security_findings,

        })


    duration_ms = int(

        (
            time.time()
            -
            started
        )

        *
        1000

    )


    log(
        "=============================================="
    )


    log(
        f"FINAL DEVICE COUNT: {len(devices)}"
    )


    for device in devices:

        label = (

            device.get(
                "friendly_name"
            )

            or

            device.get(
                "hostname"
            )

            or

            device.get(
                "model"
            )

            or

            device.get(
                "ip"
            )

        )


        log(

            "DEVICE | "
            f"{label} | "
            f"IP={device['ip']} | "
            f"MAC={device['mac']} | "
            f"VENDOR={device['vendor']} | "
            f"MODEL={device['model']} | "
            f"TYPE={device['device_type']} | "
            f"OS={device['os_guess']} | "
            f"CONF={device['identity_confidence']}% | "
            f"RULE={device['fingerprint_rule']}"

        )


    log(
        f"Scan duration: {duration_ms} ms"
    )


    log(
        "=============================================="
    )


    return {

        "devices":
            devices,

        "network":
            network,

        "local_ip":
            local_ip,

        "ruleset_version":
            ruleset_version,

        "learned_rules":
            len(
                learned_rules
            ),

        "duration_ms":
            duration_ms,

    }



# ============================================================
# DEVICE SYNC
# ============================================================

def sync_devices(

    config,

    devices

):

    return rpc(

        "agent_sync_devices",

        {

            "p_agent_id":
                config[
                    "agent_id"
                ],

            "p_agent_secret":
                config[
                    "agent_secret"
                ],

            "p_devices":
                devices,

        }

    )



# ============================================================
# VERSION CHECK
# ============================================================

def version_tuple(
    value
):

    value = (

        str(
            value
        )

        .strip()

        .lower()

        .lstrip(
            "v"
        )

    )


    match = re.match(

        r"^(\d+)"
        r"(?:\.(\d+))?"
        r"(?:\.(\d+))?",

        value

    )


    if not match:

        return (
            0,
            0,
            0
        )


    return tuple(

        int(
            part
            or
            0
        )

        for part in (
            match.groups()
        )

    )


def latest_release():

    try:

        response = requests.get(

            GITHUB_LATEST_API,

            timeout=4,

            headers={

                "Accept":
                    "application/vnd.github+json",

                "User-Agent":
                    f"WiFiWatch/{APP_VERSION}",

            }

        )


        if not response.ok:

            return None


        data = (
            response.json()
        )


        tag = (
            data.get(
                "tag_name"
            )
        )


        if not tag:

            return None


        return {

            "version":
                tag.lstrip(
                    "v"
                ),

            "url":
                (
                    data.get(
                        "html_url"
                    )

                    or

                    GITHUB_RELEASES_URL

                ),

        }


    except Exception:

        return None



# ============================================================
# GUI
# ============================================================

class WiFiWatchApp:

    def __init__(
        self
    ):

        self.root = (
            tk.Tk()
        )


        self.root.title(
            "WiFi Watch Agent"
        )


        self.root.geometry(
            "620x735"
        )


        self.root.minsize(
            530,
            590
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


        self.scan_lock = (
            threading.Lock()
        )


        self.monitor_thread = None

        self.latest_update_url = None


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


        self.devices_value = (
            tk.StringVar(
                value="0"
            )
        )


        self.identified_value = (
            tk.StringVar(
                value="0"
            )
        )


        self.rules_value = (
            tk.StringVar(
                value="—"
            )
        )


        self.learned_value = (
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


        self.update_value = (
            tk.StringVar(
                value="Checking..."
            )
        )


        self.build_ui()


        if self.is_paired():

            self.show_connected()

            self.start_monitoring()


        else:

            self.show_pairing()


        threading.Thread(

            target=
                self.check_update,

            daemon=True

        ).start()


        self.root.protocol(

            "WM_DELETE_WINDOW",

            self.close

        )


    # ========================================================
    # GUI HELPERS
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
                    else
                    "normal"
                )

            )

        )


    def is_paired(
        self
    ):

        return bool(

            self.config.get(
                "agent_id"
            )

            and

            self.config.get(
                "agent_secret"
            )

        )


    def clear_body(
        self
    ):

        for widget in (
            self.body
            .winfo_children()
        ):

            widget.destroy()


    # ========================================================
    # MAIN WINDOW
    # ========================================================

    def build_ui(
        self
    ):

        header = tk.Frame(

            self.root,

            bg="#071017"

        )


        header.pack(

            fill="x",

            padx=28,

            pady=(
                25,
                10
            )

        )


        icon = tk.Label(

            header,

            text="W",

            bg="#35e79a",

            fg="#042116",

            width=2,

            height=1,

            font=(
                "Arial",
                21,
                "bold"
            )

        )


        icon.pack(
            side="left"
        )


        titles = tk.Frame(

            header,

            bg="#071017"

        )


        titles.pack(

            side="left",

            padx=12

        )


        self.label(

            titles,

            "WiFi Watch Agent",

            18,

            True

        ).pack(
            anchor="w"
        )


        self.label(

            titles,

            (
                "Expert Device Intelligence "
                f"· v{APP_VERSION} "
                f"· Engine {ENGINE_VERSION}"
            ),

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


    # ========================================================
    # PAIRING UI
    # ========================================================

    def show_pairing(
        self
    ):

        self.clear_body()


        self.label(

            self.body,

            "Pair this computer",

            20,

            True

        ).pack(

            anchor="w",

            pady=(
                10,
                7
            )

        )


        self.label(

            self.body,

            (
                "Generate a pairing code "
                "from your WiFi Watch dashboard."
            ),

            11,

            False,

            "#8da2af"

        ).pack(

            anchor="w",

            pady=(
                0,
                22
            )

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

            pady=(
                7,
                15
            )

        )


        tk.Button(

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

            command=
                self.pair

        ).pack(

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


    def pair(
        self
    ):

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
                self.pair_worker,

            args=(
                code,
            ),

            daemon=True

        ).start()


    def pair_worker(

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

                self.pair_success

            )


        except Exception as exc:

            log(
                f"Pairing error: {exc}"
            )


            self.root.after(

                0,

                lambda:
                    self.pair_error(
                        str(
                            exc
                        )
                    )

            )


    def pair_success(
        self
    ):

        messagebox.showinfo(

            "WiFi Watch",

            "Agent paired successfully."

        )


        self.show_connected()

        self.start_monitoring()


    def pair_error(

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
    # CONNECTED UI
    # ========================================================

    def show_connected(
        self
    ):

        self.clear_body()


        self.label(

            self.body,

            "● Connected",

            13,

            True,

            "#35e79a"

        ).pack(

            anchor="w",

            pady=(
                8,
                20
            )

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
                self.devices_value
            ),

            (
                "Identified devices",
                self.identified_value
            ),

            (
                "Cloud ruleset",
                self.rules_value
            ),

            (
                "Personal learned rules",
                self.learned_value
            ),

            (
                "Security",
                self.security_value
            ),

            (
                "Last scan",
                self.scan_value
            ),

            (
                "Agent update",
                self.update_value
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

                pady=8

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


        tk.Button(

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

        ).pack(

            fill="x",

            ipady=9,

            pady=(
                20,
                9
            )

        )


        tk.Button(

            self.body,

            text=
                "Refresh Intelligence & Scan",

            bg="#182b36",

            fg="white",

            relief="flat",

            command=
                self.refresh_intelligence_scan

        ).pack(

            fill="x",

            ipady=7,

            pady=(
                0,
                9
            )

        )


        tk.Button(

            self.body,

            text=
                "Check for Agent Update",

            bg="#13232d",

            fg="white",

            relief="flat",

            command=
                self.update_button_pressed

        ).pack(

            fill="x",

            ipady=7,

            pady=(
                0,
                9
            )

        )


        self.label(

            self.body,

            (
                "Automatic scan approximately every "
                f"{SCAN_INTERVAL} seconds."
            ),

            9,

            False,

            "#8da2af"

        ).pack(
            pady=(
                4,
                5
            )
        )


        self.label(

            self.body,

            (
                "Teach WiFi Watch on the website, then use "
                "Refresh Intelligence & Scan for immediate recognition."
            ),

            9,

            False,

            "#8da2af"

        ).pack(
            pady=(
                0,
                8
            )
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
            pady=(
                0,
                15
            )
        )


        tk.Button(

            self.body,

            text=
                "Disconnect this Agent",

            bg="#13232d",

            fg="#ff8a8a",

            relief="flat",

            command=
                self.disconnect

        ).pack(

            fill="x",

            ipady=7

        )


    # ========================================================
    # MONITORING
    # ========================================================

    def start_monitoring(
        self
    ):

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


    def monitor_loop(
        self
    ):

        while not (
            self.stop_event
            .is_set()
        ):

            self.perform_scan(
                False
            )


            self.stop_event.wait(
                SCAN_INTERVAL
            )


    def manual_scan(
        self
    ):

        threading.Thread(

            target=
                self.perform_scan,

            args=(
                False,
            ),

            daemon=True

        ).start()


    def refresh_intelligence_scan(
        self
    ):

        threading.Thread(

            target=
                self.perform_scan,

            args=(
                True,
            ),

            daemon=True

        ).start()


    def perform_scan(

        self,

        force_rules=False

    ):

        if not self.is_paired():

            return


        if not self.scan_lock.acquire(
            blocking=False
        ):

            return


        started = (
            time.time()
        )


        last_local_ip = None

        ruleset = "unknown"


        try:

            self.root.after(

                0,

                lambda:
                    self.status_value.set(
                        "Expert scanning..."
                    )

            )


            heartbeat(
                self.config
            )


            result = (
                scan_network(

                    self.config,

                    force_rules=
                        force_rules

                )
            )


            devices = (
                result[
                    "devices"
                ]
            )


            network = (
                result[
                    "network"
                ]
            )


            local_ip = (
                result[
                    "local_ip"
                ]
            )


            last_local_ip = (
                local_ip
            )


            ruleset = (
                result[
                    "ruleset_version"
                ]
            )


            learned_rules = (
                result[
                    "learned_rules"
                ]
            )


            duration_ms = (
                result[
                    "duration_ms"
                ]
            )


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

                if (
                    device.get(
                        "security_status"
                    )
                    ==
                    "warning"
                )

            )


            reviews = sum(

                1

                for device in devices

                if (
                    device.get(
                        "security_status"
                    )
                    ==
                    "review"
                )

            )


            unknown_security = sum(

                1

                for device in devices

                if (
                    device.get(
                        "security_status"
                    )
                    ==
                    "unknown"
                )

            )


            report_scan(

                self.config,

                ruleset,

                duration_ms,

                len(
                    devices
                ),

                local_ip,

                None

            )


            self.root.after(

                0,

                lambda:
                    self.scan_success(

                        len(
                            devices
                        ),

                        identified,

                        str(
                            network
                        ),

                        local_ip,

                        warnings,

                        reviews,

                        unknown_security,

                        ruleset,

                        learned_rules

                    )

            )


        except Exception as exc:

            duration_ms = int(

                (
                    time.time()
                    -
                    started
                )

                *
                1000

            )


            log(
                f"SCAN ERROR: {exc}"
            )


            if self.is_paired():

                report_scan(

                    self.config,

                    ruleset,

                    duration_ms,

                    0,

                    last_local_ip,

                    str(
                        exc
                    )

                )


            self.root.after(

                0,

                lambda:
                    self.scan_error(
                        str(
                            exc
                        )
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

        reviews,

        unknown_security,

        ruleset,

        learned_rules

    ):

        self.status_value.set(
            "Online"
        )


        self.network_value.set(

            f"{network} "
            f"({local_ip})"

        )


        self.devices_value.set(
            str(
                count
            )
        )


        self.identified_value.set(

            f"{identified} / "
            f"{count}"

        )


        self.rules_value.set(
            ruleset
        )


        self.learned_value.set(
            str(
                learned_rules
            )
        )


        if warnings:

            self.security_value.set(

                f"{warnings} warning(s), "
                f"{reviews} review"

            )


        elif reviews:

            self.security_value.set(

                f"{reviews} item(s) "
                "to review"

            )


        elif unknown_security:

            self.security_value.set(

                f"{unknown_security} unknown"

            )


        else:

            self.security_value.set(

                "No obvious issues observed"

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


        self.security_value.set(
            "Scan failed"
        )


        log(
            error
        )


    # ========================================================
    # UPDATE CHECK
    # ========================================================

    def check_update(
        self
    ):

        release = (
            latest_release()
        )


        if not release:

            self.root.after(

                0,

                lambda:
                    self.update_value.set(
                        "Unable to check"
                    )

            )


            return


        latest_version = (
            release[
                "version"
            ]
        )


        if (

            version_tuple(
                latest_version
            )

            >

            version_tuple(
                APP_VERSION
            )

        ):

            self.latest_update_url = (
                release[
                    "url"
                ]
            )


            self.root.after(

                0,

                lambda:
                    self.update_value.set(

                        f"v{latest_version} available"

                    )

            )


        else:

            self.latest_update_url = None


            self.root.after(

                0,

                lambda:
                    self.update_value.set(
                        "Up to date"
                    )

            )


    def update_button_pressed(
        self
    ):

        if self.latest_update_url:

            webbrowser.open(
                self.latest_update_url
            )


            return


        self.update_value.set(
            "Checking..."
        )


        threading.Thread(

            target=
                self.check_update,

            daemon=True

        ).start()


    # ========================================================
    # DISCONNECT
    # ========================================================

    def disconnect(
        self
    ):

        if not messagebox.askyesno(

            "Disconnect Agent",

            (
                "Disconnect this computer "
                "from WiFi Watch?"
            )

        ):

            return


        self.stop_event.set()


        delete_config()


        self.config = {}


        self.show_pairing()


    def close(
        self
    ):

        self.stop_event.set()


        self.root.destroy()


    def run(
        self
    ):

        self.root.mainloop()



# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    if (

        "YOUR_REAL_"
        in
        SUPABASE_URL

        or

        "YOUR_REAL_"
        in
        SUPABASE_KEY

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
        f"{APP_VERSION}"

    )


    log(

        f"Engine version "
        f"{ENGINE_VERSION}"

    )


    app = WiFiWatchApp()

    app.run()
