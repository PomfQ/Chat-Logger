from scapy.all import AsyncSniffer, UDP, IP
from datetime import datetime
from colorama import Fore, Style, init
import re
import json

init(autoreset=True)

actor_map = {}  # Maps actor_id -> username

LOCAL_IP = ""  # Replace with your actual local_IP (IMPORTANT)
CHAT_HEADER = re.compile(b"\x62\x05\x73\x00")

def safe_decode(data):
    if not isinstance(data, bytes):
        return str(data)
    try:
        return data.decode('utf-8', errors='replace')
    except:
        return data.decode('latin1', errors='ignore')


def extract_json_bytes(data, start):
    brace_count = 0
    end = start
    while end < len(data):
        if data[end] == ord('{'):
            brace_count += 1
        elif data[end] == ord('}'):
            brace_count -= 1
            if brace_count == 0:
                return data[start:end+1]
        end += 1
    return None


def extract_join_info(payload):
    results = []
    offset = 0
    while True:
        json_start = payload.find(b'{"IsAdmin"', offset)
        if json_start == -1:
            break

        json_bytes = extract_json_bytes(payload, json_start)
        if not json_bytes:
            offset = json_start + 1
            continue

        try:
            json_str = json_bytes.decode('utf-8', errors='ignore')
            data = json.loads(json_str)
            username = data.get("UserName")
        except Exception as e:
            print(f" JSON decode failed: {e}")
            offset = json_start + 1
            continue

        # After the JSON, search forward for the next FE 69
        fe_index = payload.find(b'\xfe\x69', json_start + len(json_bytes))
        actor_id = None
        if fe_index != -1 and fe_index + 6 <= len(payload):
            actor_id = int.from_bytes(payload[fe_index + 2:fe_index + 6], 'big')

        if actor_id is not None and username:
            results.append((actor_id, username))

        offset = json_start + len(json_bytes)

    return results if results else None


def ultra_clean(payload):
    try:
        match = CHAT_HEADER.search(payload)
        if not match:
            return None
        start = match.end()
        msg_len = payload[start]
        msg = payload[start + 1 : start + 1 + msg_len]
        return ''.join(c for c in safe_decode(msg) if c.isprintable()).strip()
    except Exception as e:
        print(f"[ERROR] Cleaning message: {e}")
        return None


def extract_actor_id_after_chat(payload):
    try:
        match = CHAT_HEADER.search(payload)
        if not match:
            return None
        start = match.end()
        msg_len = payload[start]
        msg_end = start + 1 + msg_len
        if payload[msg_end:msg_end + 2] == b'\xfe\x69':
            return int.from_bytes(payload[msg_end + 2:msg_end + 6], 'big')
    except Exception as e:
        print(f" Failed to parse actor ID from chat: {e}")
    return None


def handle_self_join(payload, dst_ip): # Handles Self Join packet only. Sometimes will act as the primary function for detecting Join Info (Was Never intended to be that way but it works.)
    if dst_ip != LOCAL_IP:
        return

    offset = 0
    while True:
        json_start = payload.find(b'{"IsAdmin"', offset)
        if json_start == -1:
            break

        json_bytes = extract_json_bytes(payload, json_start)
        if not json_bytes:
            offset = json_start + 1
            continue

        try:
            data = json.loads(json_bytes.decode('utf-8', errors='ignore'))
            username = data.get("UserName")
            print(f" {Fore.RED}Scanned join username: {username}")
            if not username:
                offset = json_start + len(json_bytes)
                continue
        except:
            offset = json_start + 1
            continue

        if username in actor_map.values():
            offset = json_start + len(json_bytes)
            continue

        fe_index = payload.find(b'\xfe\x69', json_start + len(json_bytes))
        if fe_index != -1 and fe_index + 6 <= len(payload):
            actor_id = int.from_bytes(payload[fe_index + 2:fe_index + 6], 'big')
            if actor_id not in actor_map:
                actor_map[actor_id] = username
                print(f"{Fore.LIGHTBLUE_EX} Join packet: {username} (actor_id={actor_id}){Style.RESET_ALL}")
                return

        reverse_offset = 0
        while True:
            fe_index = payload.find(b'\xfe\x69', reverse_offset)
            if fe_index == -1 or fe_index + 6 > json_start:
                break
            actor_id = int.from_bytes(payload[fe_index + 2:fe_index + 6], 'big')
            if actor_id not in actor_map:
                actor_map[actor_id] = username
                print(f"{Fore.LIGHTBLUE_EX} Join packet : {username} (actor_id={actor_id}){Style.RESET_ALL}")
                return
            reverse_offset = fe_index + 6

        offset = json_start + len(json_bytes)

def packet_handler(pkt):
    if UDP in pkt:
        payload = bytes(pkt[UDP].payload)
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if src_ip == LOCAL_IP and b'{"IsAdmin"' not in payload:
            return

        # Handle join packet
        if b'{"IsAdmin"' in payload:
            handle_self_join(payload, dst_ip)
            results = extract_join_info(payload)
            if results:
                for actor_id, username in results:
                    if actor_id not in actor_map:
                        actor_map[actor_id] = username
                        print(f"{Fore.CYAN}[{datetime.now().strftime('%H:%M:%S')}] Player joined: {username} (actor_id={actor_id}){Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW} Malformed join result: None{Style.RESET_ALL}")

        # Handle chat message
        elif CHAT_HEADER.search(payload):
            msg = ultra_clean(payload)
            actor_id = extract_actor_id_after_chat(payload)

            if msg:
                if actor_id is not None and actor_id in actor_map:
                    label = f"{Fore.GREEN}{actor_map[actor_id]}{Style.RESET_ALL}"
                else:
                    label = f"{Fore.YELLOW}Actor_{actor_id if actor_id is not None else 'UNKNOWN'}{Style.RESET_ALL}"
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [{label}] {msg}")

print(f"{Fore.MAGENTA}Chat-Logger.{Style.RESET_ALL}")
sniffer = AsyncSniffer(
    filter="udp and port 5055",
    prn=packet_handler,
    store=False
)
sniffer.start()
input("Press Enter to stop...\n")
sniffer.stop()