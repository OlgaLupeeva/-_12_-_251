from __future__ import annotations

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

# DHCP Message Type (Option 53)
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


def run_cmd(cmd: List[str]) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode, p.stdout, p.stderr


def field_works(field: str) -> bool:
    """Проверяем: валидно ли поле для tshark (быстро, берём 1 пакет)."""
    cmd = ["tshark", "-r", str(PCAP_PATH), "-Y", "bootp", "-T", "fields", "-e", field, "-c", "1"]
    code, out, err = run_cmd(cmd)
    if code != 0:
        return False
    if "Some fields aren't valid" in err:
        return False
    return True


def pick_working_field(candidates: List[str]) -> Optional[str]:
    for f in candidates:
        if field_works(f):
            return f
    return None


def human_msg_type(v: Optional[str]) -> str:
    if v is None:
        return "Unknown"
    s = str(v).strip()
    if not s:
        return "Unknown"
    if s.lower().startswith("0x"):
        try:
            s = str(int(s, 16))
        except Exception:
            return s
    return DHCP_TYPE_MAP.get(s, s)


def ensure_cols(df: pd.DataFrame, cols: List[str]) -> None:
    """Если колонки нет — создаём пустую, чтобы код не падал."""
    for c in cols:
        if c not in df.columns:
            df[c] = pd.NA


def main() -> None:
    if not PCAP_PATH.exists():
        raise FileNotFoundError(f"Не найден файл дампа: {PCAP_PATH}")

    # 1) Время
    f_time = pick_working_field(["frame.time_epoch", "frame.time_relative"])
    if not f_time:
        raise RuntimeError("Не получилось найти рабочее поле времени (frame.time_epoch / frame.time_relative).")

    # 2) DHCP message type (Option 53 value)
    f_msg = pick_working_field([
        "dhcp.option.dhcp",
        "bootp.option.dhcp",
        "dhcp.option.dhcp_message_type",
        "dhcp.option.message_type",
    ])

    # 3) Остальные поля (по возможности)
    def p(cands: List[str]) -> Optional[str]:
        return pick_working_field(cands)

    f_ip_src = p(["ip.src"])
    f_ip_dst = p(["ip.dst"])
    f_xid = p(["bootp.xid"])
    f_mac = p(["bootp.hw_mac_addr", "bootp.chaddr"])
    f_yiaddr = p(["bootp.yiaddr"])
    f_siaddr = p(["bootp.siaddr"])

    f_hostname = p(["dhcp.option.hostname", "dhcp.option.host_name", "dhcp.option_host_name"])
    f_req_ip = p(["dhcp.option.requested_ip_address"])
    f_server_id = p(["dhcp.option.dhcp_server_id", "dhcp.option.server_id"])
    f_router = p(["dhcp.option.router"])
    f_dns = p(["dhcp.option.domain_name_server"])

    # 4) Таблица полей (колонка -> tshark field)
    cols: List[Tuple[str, Optional[str]]] = [
        ("time_raw", f_time),
        ("ip_src", f_ip_src),
        ("ip_dst", f_ip_dst),
        ("xid", f_xid),
        ("client_mac", f_mac),
        ("yiaddr_assigned", f_yiaddr),
        ("server_ip", f_siaddr),
        ("msg_type_raw", f_msg),
        ("hostname", f_hostname),
        ("requested_ip", f_req_ip),
        ("server_id", f_server_id),
        ("router", f_router),
        ("dns", f_dns),
    ]
    tshark_fields = [(name, f) for name, f in cols if f is not None]

    # 5) Запуск tshark
    cmd = ["tshark", "-r", str(PCAP_PATH), "-Y", "bootp", "-T", "fields"]
    cmd += ["-E", "separator=\t", "-E", "occurrence=f", "-E", "quote=n"]
    for _, f in tshark_fields:
        cmd += ["-e", f]  # type: ignore[arg-type]

    code, out, err = run_cmd(cmd)
    if code != 0:
        raise RuntimeError(f"tshark не смог прочитать дамп.\nКоманда:\n{' '.join(cmd)}\n\nstderr:\n{err}")

    # 6) Парсинг
    rows: List[Dict[str, str]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        row: Dict[str, str] = {}
        for i, (col_name, _) in enumerate(tshark_fields):
            row[col_name] = parts[i] if i < len(parts) else ""
        rows.append(row)

    df = pd.DataFrame(rows)

    # Создаём все ожидаемые колонки, чтобы нигде не падало
    ensure_cols(df, [
        "time_raw", "ip_src", "ip_dst", "xid", "client_mac", "yiaddr_assigned", "server_ip",
        "msg_type_raw", "hostname", "requested_ip", "server_id", "router", "dns"
    ])

    # 7) Время
    df["time_epoch"] = pd.to_numeric(df["time_raw"], errors="coerce")
    if f_time == "frame.time_epoch":
        df["time"] = pd.to_datetime(df["time_epoch"], unit="s", errors="coerce")
    else:
        df["time"] = pd.NaT

    # 8) Тип DHCP
    df["msg_type"] = df["msg_type_raw"].apply(lambda x: human_msg_type(x if pd.notna(x) else None))

    # server_ip: подставим server_id если пусто
    df["server_ip"] = df["server_ip"].where(df["server_ip"].astype(str).str.len() > 0, df["server_id"])

    # DEBUG
    print("DEBUG: rows total =", len(df))
    print("DEBUG: time field used =", f_time)
    print("DEBUG: time_epoch non-null =", int(df["time_epoch"].notna().sum()))
    print("DEBUG: msg field used =", f_msg)
    print("DEBUG: msg_type counts =", df["msg_type"].value_counts(dropna=False).to_dict())

    # 9) events.csv
    if df["time"].notna().any():
        df.sort_values("time", inplace=True, na_position="last")
    df.to_csv(ARTIFACTS_DIR / "dhcp_events.csv", index=False)

    # 10) leases.csv (если реально есть MAC и yiaddr)
    leases = df[df["msg_type"].isin(["ACK", "Offer"])].copy()

    # Если нет данных для leases — просто пустой файл, но без ошибок
    leases = leases.dropna(subset=["client_mac", "yiaddr_assigned"], how="any")
    leases = leases[(leases["client_mac"].astype(str).str.len() > 0) & (leases["yiaddr_assigned"].astype(str).str.len() > 0)]

    if not leases.empty:
        leases_summary = (
            leases.sort_values("time_epoch", na_position="last")
            .groupby("client_mac", as_index=False)
            .tail(1)
            .loc[:, ["client_mac", "hostname", "yiaddr_assigned", "server_ip", "time_epoch"]]
            .rename(columns={"yiaddr_assigned": "assigned_ip"})
        )
    else:
        leases_summary = pd.DataFrame(columns=["client_mac", "hostname", "assigned_ip", "server_ip", "time_epoch"])

    leases_summary.to_csv(ARTIFACTS_DIR / "dhcp_leases.csv", index=False)

    # 11) Plot 1
    plt.figure()
    df["msg_type"].fillna("Unknown").value_counts().plot(kind="bar")
    plt.title("DHCP message types (counts)")
    plt.xlabel("Message type")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(OUTPUTS_DIR / "dhcp_message_types.png", dpi=200)
    plt.close()

    # 12) Plot 2
    plt.figure()
    if f_time == "frame.time_epoch" and df["time"].notna().any():
        df_time = df.dropna(subset=["time"]).copy()
        df_time["minute"] = df_time["time"].dt.floor("min")
        series = df_time.groupby("minute").size()
        series.plot()
        plt.title("DHCP messages over time (per minute)")
        plt.xlabel("Time (minute)")
        plt.ylabel("Messages")
    else:
        df_rel = df.dropna(subset=["time_epoch"]).copy()
        if not df_rel.empty:
            t0 = df_rel["time_epoch"].min()
            df_rel["sec_from_start"] = df_rel["time_epoch"] - t0
            series = df_rel.groupby(df_rel["sec_from_start"].round(0)).size().sort_index()
            series.plot()
            plt.title("DHCP messages over time (seconds from start)")
            plt.xlabel("Seconds from start")
            plt.ylabel("Messages")
        else:
            pd.Series(range(1, len(df) + 1)).plot()
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
