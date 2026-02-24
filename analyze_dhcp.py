from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt


BASE_DIR = Path(__file__).resolve().parents[1]
PCAP_PATH = BASE_DIR / "data" / "dhcp.pcapng"

ARTIFACTS_DIR = BASE_DIR / "artifacts"
OUTPUTS_DIR = BASE_DIR / "outputs"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)


def require_tshark() -> str:
    tshark = shutil.which("tshark")
    if not tshark:
        raise RuntimeError(
            "tshark не найден. Установи Wireshark (с TShark) и добавь его в PATH.\n"
            "Проверка: tshark -v"
        )
    return tshark


def run_tshark_to_dataframe(cmd: list[str]) -> pd.DataFrame:
    """
    Запускает tshark, берёт TSV-вывод и превращает в DataFrame.
    """
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"tshark завершился с ошибкой:\n{proc.stderr}")

    text = proc.stdout.strip()
    if not text:
        return pd.DataFrame()

    # tshark -T fields с -E header=y выдаёт TSV с заголовком
    from io import StringIO
    return pd.read_csv(StringIO(text), sep="\t")


def extract_dns(tshark: str) -> pd.DataFrame:
    # DNS QUERIES (response == 0)
    cmd = [
        tshark, "-r", str(PCAP_PATH),
        "-Y", "dns && dns.flags.response==0",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=\t",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "dns.qry.name",
    ]
    df = run_tshark_to_dataframe(cmd)
    if df.empty:
        return df

    df.rename(columns={
        "frame.time_epoch": "time_epoch",
        "ip.src": "src_ip",
        "ip.dst": "dst_ip",
        "dns.qry.name": "domain",
    }, inplace=True)

    df["time_epoch"] = pd.to_numeric(df["time_epoch"], errors="coerce")
    df["time"] = pd.to_datetime(df["time_epoch"], unit="s", errors="coerce")
    return df


def extract_dhcp(tshark: str) -> pd.DataFrame:
    # DHCP/BOOTP events
    cmd = [
        tshark, "-r", str(PCAP_PATH),
        "-Y", "bootp",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=\t",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "eth.src",
        "-e", "bootp.option.dhcp",   # тип DHCP сообщения (часто цифра)
        "-e", "bootp.yiaddr",        # assigned ip
        "-e", "bootp.xid",
    ]
    df = run_tshark_to_dataframe(cmd)
    if df.empty:
        return df

    df.rename(columns={
        "frame.time_epoch": "time_epoch",
        "ip.src": "src_ip",
        "ip.dst": "dst_ip",
        "eth.src": "client_mac",
        "bootp.option.dhcp": "dhcp_type_raw",
        "bootp.yiaddr": "assigned_ip",
        "bootp.xid": "xid",
    }, inplace=True)

    # Карта типов DHCP (если приходит числом)
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
    df["dhcp_type_raw"] = df["dhcp_type_raw"].astype(str).str.strip()
    df["dhcp_type"] = df["dhcp_type_raw"].map(dhcp_type_map).fillna(df["dhcp_type_raw"])

    df["time_epoch"] = pd.to_numeric(df["time_epoch"], errors="coerce")
    df["time"] = pd.to_datetime(df["time_epoch"], unit="s", errors="coerce")
    return df


def plot_dns(df_dns: pd.DataFrame) -> None:
    # 1) DNS по времени (по минутам)
    df = df_dns.dropna(subset=["time"]).copy()
    if df.empty:
        return

    df["minute"] = df["time"].dt.floor("min")
    series = df.groupby("minute").size()

    plt.figure()
    series.plot()
    plt.xlabel("Time (minute)")
    plt.ylabel("DNS queries")
    plt.title("DNS queries over time")
    plt.tight_layout()
    plt.savefig(OUTPUTS_DIR / "dns_requests_over_time.png", dpi=200)
    plt.close()

    # 2) Топ доменов
    top = df["domain"].dropna().astype(str).value_counts().head(10)
    if not top.empty:
        plt.figure()
        top.plot(kind="bar")
        plt.xlabel("Domain")
        plt.ylabel("Count")
        plt.title("Top-10 DNS domains")
        plt.tight_layout()
        plt.savefig(OUTPUTS_DIR / "top_domains.png", dpi=200)
        plt.close()


def plot_dhcp(df_dhcp: pd.DataFrame) -> None:
    df = df_dhcp.copy()
    if df.empty:
        return
    counts = df["dhcp_type"].fillna("Unknown").value_counts()

    plt.figure()
    counts.plot(kind="bar")
    plt.xlabel("DHCP message type")
    plt.ylabel("Count")
    plt.title("DHCP message types (counts)")
    plt.tight_layout()
    plt.savefig(OUTPUTS_DIR / "dhcp_message_types.png", dpi=200)
    plt.close()


def main() -> None:
    if not PCAP_PATH.exists():
        raise FileNotFoundError(f"Не найден файл дампа: {PCAP_PATH}")

    tshark = require_tshark()

    # --- DNS (как в ноутбуке) ---
    df_dns = extract_dns(tshark)
    (ARTIFACTS_DIR / "dns_requests.csv").write_text("", encoding="utf-8")  # чтобы файл был даже если пусто
    if not df_dns.empty:
        df_dns.to_csv(ARTIFACTS_DIR / "dns_requests.csv", index=False)

    # --- DHCP (значимые события из твоего дампа) ---
    df_dhcp = extract_dhcp(tshark)
    (ARTIFACTS_DIR / "dhcp_events.csv").write_text("", encoding="utf-8")
    if not df_dhcp.empty:
        df_dhcp.to_csv(ARTIFACTS_DIR / "dhcp_events.csv", index=False)

    # --- Визуализации ---
    plot_dns(df_dns)
    plot_dhcp(df_dhcp)

    print("OK. Saved:")
    print("  artifacts/dns_requests.csv  (rows:", len(df_dns), ")")
    print("  artifacts/dhcp_events.csv   (rows:", len(df_dhcp), ")")
    print("  outputs/*.png")


if __name__ == "__main__":
    main()
