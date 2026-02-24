from __future__ import annotations

import csv
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
# Маппинг DHCP Message Type (Option 53)
# -----------------------------
DHCP_TYPE_MAP = {
    "1": "Discover",
    "2": "Offer",
    "3": "Request",
    "4": "Decline",
    "5": "ACK",
    "6": "NAK",
    "7": "Release",
    "8": "Inform",
}


# -----------------------------
# Вспомогательные функции
# -----------------------------
def run_cmd(cmd: List[str]) -> Tuple[int, str, str]:
    """Запускает команду и возвращает (код, stdout, stderr)."""
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode, p.stdout, p.stderr


def get_tshark_fields_set() -> set:
    """
    Получаем список всех полей tshark (tshark -G fields),
    чтобы потом выбирать правильные имена полей под твою версию Wireshark.
    """
    code, out, err = run_cmd(["tshark", "-G", "fields"])
    if code != 0:
        raise RuntimeError(
            "Не удалось выполнить 'tshark -G fields'.\n"
            f"stderr:\n{err}\n"
            "Проверь, что Wireshark установлен и tshark доступен в PATH."
        )

    fields = set()
    # Формат строк примерно: F <field_name>\t<...>
    for line in out.splitlines():
        if line.startswith("F\t"):
            parts = line.split("\t")
            if len(parts) >= 2:
                fields.add(parts[1].strip())
    return fields


def pick_first_existing(fields_set: set, candidates: List[str]) -> Optional[str]:
    """Возвращает первое поле из candidates, которое реально существует в tshark."""
    for f in candidates:
        if f in fields_set:
            return f
    return None


def human_msg_type(v: Optional[str]) -> str:
    if v is None or v == "":
        return "Unknown"
    v = v.strip()
    # Иногда tshark может вернуть "1" или "0x01" или "Discover" — сделаем аккуратно.
    if v.lower().startswith("0x"):
        try:
            v = str(int(v, 16))
        except Exception:
            return v
    return DHCP_TYPE_MAP.get(v, v)


# -----------------------------
# Основная логика
# -----------------------------
def main() -> None:
    if not PCAP_PATH.exists():
        raise FileNotFoundError(f"Не найден файл дампа: {PCAP_PATH}")

    # 1) Узнаём, какие поля есть в твоём tshark
    fields_set = get_tshark_fields_set()

    # 2) Выбираем реальные поля под твою версию Wireshark
    # Время (epoch)
    f_time = pick_first_existing(fields_set, ["frame.time_epoch"])
    if not f_time:
        raise RuntimeError("В твоём tshark не найдено поле frame.time_epoch (очень странно).")

    # DHCP message type (Option 53 value)
    # На разных версиях встречаются разные имена — поэтому список кандидатов.
    f_msg_type = pick_first_existing(
        fields_set,
        [
            "dhcp.option.dhcp",                     # часто работает
            "bootp.option.dhcp",                    # иногда DHCP остаётся в bootp
            "dhcp.option.dhcp_message_type",        # у некоторых версий
            "dhcp.option.message_type",             # редкий вариант
        ],
    )

    # IP источника/назначения
    f_ip_src = pick_first_existing(fields_set, ["ip.src"])
    f_ip_dst = pick_first_existing(fields_set, ["ip.dst"])

    # BOOTP/DHCP поля
    f_xid = pick_first_existing(fields_set, ["bootp.xid"])
    f_hw = pick_first_existing(fields_set, ["bootp.hw_mac_addr", "bootp.chaddr"])
    f_yiaddr = pick_first_existing(fields_set, ["bootp.yiaddr"])
    f_siaddr = pick_first_existing(fields_set, ["bootp.siaddr"])

    # DHCP options
    f_hostname = pick_first_existing(fields_set, ["dhcp.option.hostname", "dhcp.option_host_name", "dhcp.option.host_name"])
    f_req_ip = pick_first_existing(fields_set, ["dhcp.option.requested_ip_address"])
    f_server_id = pick_first_existing(fields_set, ["dhcp.option.dhcp_server_id", "dhcp.option.server_id"])
    f_router = pick_first_existing(fields_set, ["dhcp.option.router"])
    f_dns = pick_first_existing(fields_set, ["dhcp.option.domain_name_server"])

    # 3) Собираем список полей, которые будем вытаскивать
    # Важно: tshark выдаёт значения в том порядке, в котором идут -e
    fields_order: List[Tuple[str, Optional[str]]] = [
        ("time_epoch", f_time),
        ("ip_src", f_ip_src),
        ("ip_dst", f_ip_dst),
        ("xid", f_xid),
        ("client_mac", f_hw),
        ("yiaddr_assigned", f_yiaddr),
        ("server_ip", f_siaddr),
        ("msg_type_raw", f_msg_type),
        ("hostname", f_hostname),
        ("requested_ip", f_req_ip),
        ("server_id", f_server_id),
        ("router", f_router),
        ("dns", f_dns),
    ]

    # Оставим только реально существующие поля (None убираем)
    tshark_fields = [(name, f) for name, f in fields_order if f is not None]

    # 4) Запускаем tshark и вытаскиваем таблицу
    cmd = ["tshark", "-r", str(PCAP_PATH), "-Y", "bootp", "-T", "fields"]
    # Чтобы поля нормально разделялись:
    cmd += ["-E", "separator=\t", "-E", "occurrence=f", "-E", "quote=n"]
    for _, f in tshark_fields:
        cmd += ["-e", f]  # type: ignore[arg-type]

    code, out, err = run_cmd(cmd)
    if code != 0:
        raise RuntimeError(
            "tshark не смог прочитать дамп или поля.\n"
            f"Команда:\n{' '.join(cmd)}\n\n"
            f"stderr:\n{err}"
        )

    # 5) Парсим вывод в список словарей
    rows: List[Dict[str, str]] = []
    lines = [ln for ln in out.splitlines() if ln.strip() != ""]
    for ln in lines:
        parts = ln.split("\t")
        row: Dict[str, str] = {}
        for i, (col_name, _) in enumerate(tshark_fields):
            row[col_name] = parts[i] if i < len(parts) else ""
        rows.append(row)

    # 6) DataFrame + нормализация
    df = pd.DataFrame(rows)

    # time_epoch -> float
    if "time_epoch" in df.columns:
        df["time_epoch"] = pd.to_numeric(df["time_epoch"], errors="coerce")

    # msg_type -> человекочитаемо
    if "msg_type_raw" in df.columns:
        df["msg_type"] = df["msg_type_raw"].apply(lambda x: human_msg_type(x if pd.notna(x) else None))
    else:
        df["msg_type"] = "Unknown"

    # server_ip: если siaddr пустой, подставим server_id
    if "server_ip" in df.columns and "server_id" in df.columns:
        df["server_ip"] = df["server_ip"].where(df["server_ip"].astype(str).str.len() > 0, df["server_id"])

    # time (datetime)
    df["time"] = pd.to_datetime(df.get("time_epoch"), unit="s", errors="coerce")

    # DEBUG (чтобы видеть, что время и типы реально появились)
    print("DEBUG: rows total =", len(df))
    print("DEBUG: time_epoch non-null =", int(df["time_epoch"].notna().sum()) if "time_epoch" in df.columns else 0)
    print("DEBUG: time non-null =", int(df["time"].notna().sum()))
    print("DEBUG: msg_type unique =", df["msg_type"].value_counts(dropna=False).to_dict())

    # 7) Сохраняем events
    df.sort_values("time", inplace=True, na_position="last")
    df.to_csv(ARTIFACTS_DIR / "dhcp_events.csv", index=False)

    # 8) leases (по ACK/OFFER)
    leases = df[df["msg_type"].isin(["ACK", "Offer"])].copy()
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

    # 9) Plot 1: типы сообщений
    plt.figure()
    df["msg_type"].fillna("Unknown").value_counts().plot(kind="bar")
    plt.title("DHCP message types (counts)")
    plt.xlabel("Message type")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(OUTPUTS_DIR / "dhcp_message_types.png", dpi=200)
    plt.close()

    # 10) Plot 2: активность во времени (по минутам)
    plt.figure()
    df_time = df.dropna(subset=["time"]).copy()
    if not df_time.empty:
        df_time["minute"] = df_time["time"].dt.floor("min")
        series = df_time.groupby("minute").size()
        series.plot()
        plt.title("DHCP messages over time (per minute)")
        plt.xlabel("Time (minute)")
        plt.ylabel("Messages")
    else:
        # На случай, если внезапно времени не будет (маловероятно с tshark)
        series = pd.Series(range(1, len(df) + 1))
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
