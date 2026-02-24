from __future__ import annotations

import sys
import asyncio
from pathlib import Path
from typing import Any, Optional, Dict, List

import pandas as pd
import matplotlib.pyplot as plt


# -----------------------------
# Пути проекта
# -----------------------------
BASE_DIR = Path(__file__).resolve().parents[1]
PCAP_PATH = BASE_DIR / "data" / "dhcp.pcapng"

ARTIFACTS_DIR = BASE_DIR / "artifacts"
OUTPUTS_DIR = BASE_DIR / "outputs"

ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)


# -----------------------------
# Безопасное извлечение полей из pyshark
# -----------------------------
def safe_layer(pkt: Any, layer_name: str) -> Optional[Any]:
    try:
        return getattr(pkt, layer_name)
    except Exception:
        return None


def safe_get(pkt: Any, layer_name: str, field_name: str) -> Optional[str]:
    """
    Пытаемся достать поле из слоя.
    Возвращаем строку или None.
    """
    layer = safe_layer(pkt, layer_name)
    if layer is None:
        return None

    # 1) как атрибут
    try:
        if hasattr(layer, field_name):
            v = getattr(layer, field_name)
            if v is None:
                return None
            return str(v)
    except Exception:
        pass

    # 2) через get_field_value (если есть)
    try:
        if hasattr(layer, "get_field_value"):
            v = layer.get_field_value(field_name)
            if v is None:
                return None
            return str(v)
    except Exception:
        pass

    return None


def safe_expr(pkt: Any, expr: str) -> Optional[str]:
    """
    expr формата: 'ip.src' или 'bootp.yiaddr'
    """
    try:
        layer_name, field_name = expr.split(".", 1)
        return safe_get(pkt, layer_name, field_name)
    except Exception:
        return None


def sniff_epoch(pkt: Any) -> Optional[float]:
    try:
        return float(pkt.sniff_timestamp)
    except Exception:
        return None


# -----------------------------
# Главная логика
# -----------------------------
def main() -> None:
    # Импортируем тут, чтобы при проблеме было понятнее
    import pyshark  # type: ignore

    if not PCAP_PATH.exists():
        raise FileNotFoundError(f"Не найден дамп: {PCAP_PATH}")

    # ---- FIX: Windows + Python 3.12 + pyshark (asyncio loop) ----
    # В 3.12 на Windows часто нет "текущего event loop" по умолчанию.
    # Создаём его вручную и передаём в FileCapture.
    loop: Optional[asyncio.AbstractEventLoop] = None
    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # DHCP в Wireshark обычно идёт как BOOTP (display_filter="bootp")
    # Если вдруг дамп специфичный, можно расширить фильтр: "bootp || dhcp"
    cap = pyshark.FileCapture(
        str(PCAP_PATH),
        display_filter="bootp",
        keep_packets=False,
        use_json=True,
        include_raw=False,
        eventloop=loop,  # <-- ключевой фикс
    )

    # DHCP msg type mapping
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

    events: List[Dict[str, Any]] = []

    try:
        for pkt in cap:
            t_epoch = sniff_epoch(pkt)

            # IP-адреса иногда отсутствуют (особенно на ранних этапах DHCP)
            ip_src = safe_expr(pkt, "ip.src")
            ip_dst = safe_expr(pkt, "ip.dst")

            # BOOTP/DHCP основные поля
            xid = safe_expr(pkt, "bootp.xid")

            # MAC клиента может быть в разных полях
            client_mac = safe_expr(pkt, "bootp.hw_mac_addr")
            if client_mac is None:
                client_mac = safe_expr(pkt, "bootp.chaddr")

            yiaddr = safe_expr(pkt, "bootp.yiaddr")  # выданный IP (your IP)
            siaddr = safe_expr(pkt, "bootp.siaddr")  # IP сервера (иногда)

            # DHCP message type: встречается в dhcp.option_dhcp_message_type или похожих
            msg_type_raw = (
                safe_expr(pkt, "dhcp.option_dhcp_message_type")
                or safe_expr(pkt, "bootp.option_dhcp_message_type")
                or safe_expr(pkt, "dhcp.option_dhcp")
                or safe_expr(pkt, "bootp.option_dhcp")
            )

            msg_type_raw_str = str(msg_type_raw).strip() if msg_type_raw is not None else None
            msg_type = dhcp_type_map.get(msg_type_raw_str, msg_type_raw_str or "Unknown")

            # Опции (могут отсутствовать)
            hostname = (
                safe_expr(pkt, "dhcp.option_hostname")
                or safe_expr(pkt, "bootp.option_hostname")
            )
            requested_ip = (
                safe_expr(pkt, "dhcp.option_requested_ip_address")
                or safe_expr(pkt, "bootp.option_requested_ip_address")
            )
            server_id = (
                safe_expr(pkt, "dhcp.option_dhcp_server_id")
                or safe_expr(pkt, "bootp.option_dhcp_server_id")
            )
            router = (
                safe_expr(pkt, "dhcp.option_router")
                or safe_expr(pkt, "bootp.option_router")
            )
            dns = (
                safe_expr(pkt, "dhcp.option_domain_name_server")
                or safe_expr(pkt, "bootp.option_domain_name_server")
            )

            events.append(
                {
                    "time_epoch": t_epoch,
                    "ip_src": ip_src,
                    "ip_dst": ip_dst,
                    "xid": xid,
                    "client_mac": client_mac,
                    "msg_type": msg_type,
                    "yiaddr_assigned": yiaddr,
                    "server_ip": siaddr or server_id,
                    "requested_ip": requested_ip,
                    "hostname": hostname,
                    "router": router,
                    "dns": dns,
                }
            )
    finally:
        # Правильно закрываем захват + event loop
        try:
            cap.close()
        except Exception:
            pass
        try:
            loop.close()
        except Exception:
            pass

    # Если пакетов не нашлось — создадим пустые файлы и выйдем без падения
    df = pd.DataFrame(events)
    if df.empty:
        empty_path = ARTIFACTS_DIR / "dhcp_events.csv"
        df.to_csv(empty_path, index=False)
        print("В дампе не найдено BOOTP/DHCP пакетов по фильтру 'bootp'.")
        print(f"Создан пустой файл: {empty_path}")
        print("Если уверена, что DHCP есть — поменяй display_filter на 'bootp || dhcp'.")
        return

    # Время
    df["time"] = pd.to_datetime(df["time_epoch"], unit="s", errors="coerce")
    df.sort_values("time", inplace=True)

    # 1) Полный лог событий
    df.to_csv(ARTIFACTS_DIR / "dhcp_events.csv", index=False)

    # 2) “Аренды” (leases) — по Offer/ACK
    leases = df[df["msg_type"].isin(["Offer", "ACK"])].copy()
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
    # Визуализация 1: типы DHCP сообщений
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
    # Визуализация 2: активность по минутам
    # -----------------------------
    df_time = df.dropna(subset=["time"]).copy()
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

    # Итог в консоль (удобно для отчёта)
    print("OK: dhcp_events.csv ->", ARTIFACTS_DIR / "dhcp_events.csv")
    print("OK: dhcp_leases.csv ->", ARTIFACTS_DIR / "dhcp_leases.csv")
    print("OK: plots ->", OUTPUTS_DIR)
    print("\nКраткая сводка:")
    print("Всего DHCP/BOOTP пакетов:", len(df))
    print("Уникальных MAC клиентов:", df["client_mac"].nunique(dropna=True))
    print("Типы сообщений:\n", type_counts.to_string())


if __name__ == "__main__":
    main()
