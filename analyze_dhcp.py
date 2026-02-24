from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional, Dict, List

import pandas as pd
import matplotlib.pyplot as plt

# -----------------------------
# Настройки путей
# -----------------------------
BASE_DIR = Path(__file__).resolve().parents[1]
PCAP_PATH = BASE_DIR / "data" / "dhcp.pcapng"
ARTIFACTS_DIR = BASE_DIR / "artifacts"
OUTPUTS_DIR = BASE_DIR / "outputs"

ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

# -----------------------------
# Утилиты для безопасного извлечения полей pyshark
# -----------------------------
def _safe_get(pkt: Any, layer_name: str, field: str) -> Optional[str]:
    """
    Пробует достать поле из указанного слоя.
    Возвращает строку или None.
    """
    try:
        layer = getattr(pkt, layer_name)
        # pyshark иногда хранит поля как атрибуты, иногда как словарь
        if hasattr(layer, field):
            return str(getattr(layer, field))
        # fallback: попытка через get_field_value (если доступно)
        if hasattr(layer, "get_field_value"):
            v = layer.get_field_value(field)
            return str(v) if v is not None else None
        return None
    except Exception:
        return None


def _safe(pkt: Any, expr: str) -> Optional[str]:
    """
    expr вида: "ip.src" или "bootp.yiaddr"
    """
    try:
        layer_name, field = expr.split(".", 1)
        return _safe_get(pkt, layer_name, field)
    except Exception:
        return None


def normalize_epoch(pkt: Any) -> Optional[float]:
    try:
        # sniff_timestamp = str epoch
        return float(pkt.sniff_timestamp)
    except Exception:
        return None


# -----------------------------
# Основной парсинг
# -----------------------------
def main() -> None:
    # Импорт здесь, чтобы ошибка была понятнее (и чтобы файл открывался даже без pyshark)
    import pyshark  # type: ignore

    if not PCAP_PATH.exists():
        raise FileNotFoundError(f"Не найден файл дампа: {PCAP_PATH}")

    # Важно: display_filter = "bootp" обычно покрывает DHCP
    cap = pyshark.FileCapture(
        str(PCAP_PATH),
        display_filter="bootp",
        keep_packets=False,
        use_json=True,          # быстрее/стабильнее для полей
        include_raw=False
    )

    events: List[Dict[str, Any]] = []

    # DHCP message type mapping (по числу, если вытащится именно число)
    dhcp_type_map = {
        "1": "Discover",
        "2": "Offer",
        "3": "Request",
        "4": "Decline",
        "5": "ACK",
        "6": "NAK",
        "7": "Release",
        "8": "Inform",
    }

    for pkt in cap:
        # Время
        t_epoch = normalize_epoch(pkt)

        # IP-адреса (могут отсутствовать, если это совсем ранний этап)
        ip_src = _safe(pkt, "ip.src")
        ip_dst = _safe(pkt, "ip.dst")

        # Основные BOOTP/DHCP поля
        xid = _safe(pkt, "bootp.xid")                 # transaction id
        client_mac = _safe(pkt, "bootp.hw_mac_addr")  # иногда так
        if client_mac is None:
            # альтернативные варианты названий поля
            client_mac = _safe(pkt, "bootp.chaddr")

        yiaddr = _safe(pkt, "bootp.yiaddr")           # "your (client) IP address"
        siaddr = _safe(pkt, "bootp.siaddr")           # server IP (иногда)

        # DHCP options (могут быть не у всех пакетов)
        dhcp_msg_type = _safe(pkt, "dhcp.option_dhcp")  # иногда так
        if dhcp_msg_type is None:
            dhcp_msg_type = _safe(pkt, "bootp.option_dhcp")

        # Иногда msg_type приходит как "1" / "3" и т.п.
        dhcp_msg_type_human = dhcp_type_map.get(str(dhcp_msg_type), str(dhcp_msg_type))

        hostname = _safe(pkt, "dhcp.option_hostname")
        requested_ip = _safe(pkt, "dhcp.option_requested_ip_address")
        server_id = _safe(pkt, "dhcp.option_dhcp_server_id")
        router = _safe(pkt, "dhcp.option_router")
        dns = _safe(pkt, "dhcp.option_domain_name_server")

        events.append({
            "time_epoch": t_epoch,
            "ip_src": ip_src,
            "ip_dst": ip_dst,
            "xid": xid,
            "client_mac": client_mac,
            "msg_type": dhcp_msg_type_human,
            "yiaddr_assigned": yiaddr,
            "server_ip": siaddr or server_id,
            "requested_ip": requested_ip,
            "hostname": hostname,
            "router": router,
            "dns": dns,
        })

    df = pd.DataFrame(events)

    # Нормализуем время
    df["time"] = pd.to_datetime(df["time_epoch"], unit="s", errors="coerce")

    # Сохраняем «лог артефактов»
    df.sort_values("time", inplace=True)
    df.to_csv(ARTIFACTS_DIR / "dhcp_events.csv", index=False)

    # -----------------------------
    # Сбор "выданных аренд" (leases) из ACK/OFFER
    # -----------------------------
    leases = df[df["msg_type"].isin(["ACK", "Offer"])].copy()
    # Группировка: для каждого MAC — последний выданный yiaddr
    leases_summary = (
        leases.dropna(subset=["client_mac", "yiaddr_assigned"])
              .sort_values("time")
              .groupby("client_mac", as_index=False)
              .tail(1)
              .loc[:, ["client_mac", "hostname", "yiaddr_assigned", "server_ip", "time"]]
              .rename(columns={"yiaddr_assigned": "assigned_ip"})
    )
    leases_summary.to_csv(ARTIFACTS_DIR / "dhcp_leases.csv", index=False)

    # -----------------------------
    # Визуализация 1: количество DHCP-сообщений по типам
    # -----------------------------
    type_counts = df["msg_type"].fillna("Unknown").value_counts()

    plt.figure()
    type_counts.plot(kind="bar")
    plt.title("DHCP message types (counts)")
    plt.xlabel("Message type")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(OUTPUTS_DIR / "dhcp_message_types.png", dpi=200)
    plt.close()

    # -----------------------------
    # Визуализация 2: активность во времени (по минутам)
    # -----------------------------
    df_time = df.dropna(subset=["time"]).copy()
    if not df_time.empty:
        df_time["minute"] = df_time["time"].dt.floor("min")
        series = df_time.groupby("minute").size()

        plt.figure()
        series.plot()
        plt.title("DHCP messages over time (per minute)")
        plt.xlabel("Time (minute)")
        plt.ylabel("Messages")
        plt.tight_layout()
        plt.savefig(OUTPUTS_DIR / "dhcp_messages_over_time.png", dpi=200)
        plt.close()

    print("OK: artifacts saved to:", ARTIFACTS_DIR)
    print("OK: plots saved to:", OUTPUTS_DIR)


if __name__ == "__main__":
    main()
