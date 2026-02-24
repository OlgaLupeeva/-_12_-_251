from __future__ import annotations

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
    """Пробует достать поле из указанного слоя. Возвращает строку или None."""
    try:
        layer = getattr(pkt, layer_name)
        if hasattr(layer, field):
            return str(getattr(layer, field))
        if hasattr(layer, "get_field_value"):
            v = layer.get_field_value(field)
            return str(v) if v is not None else None
        return None
    except Exception:
        return None


def _safe(pkt: Any, expr: str) -> Optional[str]:
    """expr вида: 'ip.src' или 'bootp.yiaddr'"""
    try:
        layer_name, field = expr.split(".", 1)
        return _safe_get(pkt, layer_name, field)
    except Exception:
        return None


def normalize_epoch(pkt: Any) -> Optional[float]:
    """Достаём время пакета в epoch (секунды)."""
    # Основной вариант
    try:
        v = getattr(pkt, "sniff_timestamp", None)
        if v is not None:
            return float(v)
    except Exception:
        pass

    # Фолбэк: sniff_time -> datetime
    try:
        st = getattr(pkt, "sniff_time", None)
        if st is not None:
            return float(st.timestamp())
    except Exception:
        pass

    return None


# -----------------------------
# Основной парсинг
# -----------------------------
def main() -> None:
    # Импорт здесь, чтобы файл открывался даже без pyshark
    import pyshark  # type: ignore
    import asyncio

    if not PCAP_PATH.exists():
        raise FileNotFoundError(f"Не найден файл дампа: {PCAP_PATH}")

    # Фикс для Python 3.14 / asyncio: создаём event loop явно
    asyncio.set_event_loop(asyncio.new_event_loop())

    # Важно: display_filter = "bootp" обычно покрывает DHCP
    cap = pyshark.FileCapture(
        str(PCAP_PATH),
        display_filter="bootp",
        keep_packets=False,
        use_json=True,
        include_raw=False,
    )

    events: List[Dict[str, Any]] = []

    # DHCP message type mapping
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
        t_epoch = normalize_epoch(pkt)

        ip_src = _safe(pkt, "ip.src")
        ip_dst = _safe(pkt, "ip.dst")

        xid = _safe(pkt, "bootp.xid")
        client_mac = _safe(pkt, "bootp.hw_mac_addr") or _safe(pkt, "bootp.chaddr")

        yiaddr = _safe(pkt, "bootp.yiaddr")
        siaddr = _safe(pkt, "bootp.siaddr")

        # msg type
        dhcp_msg_type = _safe(pkt, "dhcp.option_dhcp") or _safe(pkt, "bootp.option_dhcp")
        dhcp_msg_type_human = dhcp_type_map.get(str(dhcp_msg_type), str(dhcp_msg_type) if dhcp_msg_type is not None else None)

        hostname = _safe(pkt, "dhcp.option_hostname")
        requested_ip = _safe(pkt, "dhcp.option_requested_ip_address")
        server_id = _safe(pkt, "dhcp.option_dhcp_server_id")
        router = _safe(pkt, "dhcp.option_router")
        dns = _safe(pkt, "dhcp.option_domain_name_server")

        events.append(
            {
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
            }
        )

    df = pd.DataFrame(events)

    # Нормализуем время
    df["time"] = pd.to_datetime(df["time_epoch"], unit="s", errors="coerce")

    # DEBUG (можешь потом убрать)
    print("DEBUG: rows total =", len(df))
    if "time_epoch" in df.columns:
        print("DEBUG: time_epoch non-null =", int(df["time_epoch"].notna().sum()))
    if "time" in df.columns:
        print("DEBUG: time non-null =", int(df["time"].notna().sum()))

    # Сохраняем «лог артефактов»
    if not df.empty and "time" in df.columns:
        df.sort_values("time", inplace=True)
    df.to_csv(ARTIFACTS_DIR / "dhcp_events.csv", index=False)

    # -----------------------------
    # Leases (ACK/OFFER)
    # -----------------------------
    if not df.empty and "msg_type" in df.columns:
        leases = df[df["msg_type"].isin(["ACK", "Offer"])].copy()
    else:
        leases = df.copy()

    if not leases.empty:
        leases_summary = (
            leases.dropna(subset=["client_mac", "yiaddr_assigned"])
            .sort_values("time", na_position="last")
            .groupby("client_mac", as_index=False)
            .tail(1)
            .loc[:, ["client_mac", "hostname", "yiaddr_assigned", "server_ip", "time"]]
            .rename(columns={"yiaddr_assigned": "assigned_ip"})
        )
    else:
        leases_summary = pd.DataFrame(columns=["client_mac", "hostname", "assigned_ip", "server_ip", "time"])

    leases_summary.to_csv(ARTIFACTS_DIR / "dhcp_leases.csv", index=False)

    # -----------------------------
    # Визуализация 1: количество DHCP-сообщений по типам
    # -----------------------------
    if not df.empty and "msg_type" in df.columns:
        type_counts = df["msg_type"].fillna("Unknown").value_counts()
    else:
        type_counts = pd.Series(dtype=int)

    plt.figure()
    if not type_counts.empty:
        type_counts.plot(kind="bar")
    plt.title("DHCP message types (counts)")
    plt.xlabel("Message type")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(OUTPUTS_DIR / "dhcp_message_types.png", dpi=200)
    plt.close()

    # -----------------------------
    # Визуализация 2: активность во времени
    #   - если время есть → по минутам
    #   - если времени нет → по порядку пакетов (fallback)
    # -----------------------------
    plt.figure()

    if not df.empty and df["time"].notna().any():
        df_time = df.dropna(subset=["time"]).copy()
        df_time["minute"] = df_time["time"].dt.floor("min")
        series = df_time.groupby("minute").size()
        series.plot()
        plt.title("DHCP messages over time (per minute)")
        plt.xlabel("Time (minute)")
        plt.ylabel("Messages")
    else:
        series = pd.Series(range(1, len(df) + 1), index=range(len(df)))
        series.plot()
        plt.title("DHCP messages over capture order")
        plt.xlabel("Packet index")
        plt.ylabel("Cumulative messages")

    plt.tight_layout()
    plt.savefig(OUTPUTS_DIR / "dhcp_message_over_time.png", dpi=200)
    plt.close()

    print("OK: artifacts saved to:", ARTIFACTS_DIR)
    print("OK: plots saved to:", OUTPUTS_DIR)


if __name__ == "__main__":
    main()
