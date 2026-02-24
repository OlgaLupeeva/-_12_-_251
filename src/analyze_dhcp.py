from __future__ import annotations

import shutil
import subprocess
import re
from pathlib import Path
from typing import List, Tuple, Optional, Dict

import pandas as pd
import matplotlib.pyplot as plt


# -----------------------------
# Пути проекта
# -----------------------------
BASE_DIR = Path(__file__).resolve().parents[1]
PCAP_PATH = BASE_DIR / "data" / "dhcp.pcapng"

ARTIFACTS_DIR = BASE_DIR / "artifacts"
OUTPUTS_DIR = BASE_DIR / "outputs"
REPORT_DIR = BASE_DIR / "report"

ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


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


def require_tshark() -> str:
    tshark = shutil.which("tshark")
    if not tshark:
        raise RuntimeError(
            "tshark не найден. Установи Wireshark (с TShark) и добавь его в PATH.\n"
            "Проверка: tshark -v"
        )
    return tshark


def tshark_tsv(tshark: str, display_filter: str, fields: List[str], limit: Optional[int] = None) -> pd.DataFrame:
    cmd = [
        tshark, "-r", str(PCAP_PATH),
        "-Y", display_filter,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=\t",
        "-E", "occurrence=f",
        "-E", "quote=n",
    ]
    if limit is not None:
        cmd += ["-c", str(limit)]
    for f in fields:
        cmd += ["-e", f]

    code, out, err = run_cmd(cmd)
    if code != 0:
        raise RuntimeError(f"tshark error\nCMD: {' '.join(cmd)}\n\nstderr:\n{err}")

    out = out.strip()
    if not out:
        return pd.DataFrame()

    from io import StringIO
    return pd.read_csv(StringIO(out), sep="\t")


# -----------------------------
# DHCP Message Type из verbose (-V) как в Wireshark
# -----------------------------
def dhcp_types_from_verbose(tshark: str) -> Dict[int, str]:
    """
    Парсим tshark -V и вытаскиваем DHCP Message Type (Option 53) по кадрам.
    Возвращает mapping {frame_no: "Discover"/...}
    """
    code, out, err = run_cmd([tshark, "-r", str(PCAP_PATH), "-Y", "bootp || dhcp", "-V"])
    if code != 0 or not out.strip():
        return {}

    mapping: Dict[int, str] = {}
    parts = re.split(r"\nFrame\s+(\d+):", out)
    # parts: [before_first, "1", body1, "2", body2, ...]
    for i in range(1, len(parts), 2):
        try:
            frame_no = int(parts[i])
            body = parts[i + 1]
        except Exception:
            continue

        # Ищем "(53) DHCP Message Type ... (3)" или "DHCP Message Type ... (3)"
        m = re.search(r"DHCP\s+Message\s+Type.*?\((\d)\)", body, flags=re.IGNORECASE)
        if m:
            num = m.group(1)
            mapping[frame_no] = DHCP_TYPE_MAP.get(num, num)

    return mapping


# -----------------------------
# Артефакты: DNS queries (если есть)
# -----------------------------
def extract_dns_queries(tshark: str) -> pd.DataFrame:
    df = tshark_tsv(
        tshark,
        "dns && dns.flags.response==0",
        ["frame.time_epoch", "ip.src", "ip.dst", "dns.qry.name"],
    )
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


# -----------------------------
# Артефакты: DHCP events + IP + DNS options
# -----------------------------
def extract_dhcp(tshark: str) -> pd.DataFrame:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "eth.src",
        "bootp.yiaddr",
        "bootp.siaddr",
        "bootp.option.dhcp",              # может быть не type, но пусть будет
        "dhcp.option.domain_name_server", # Option 6
        "dhcp.option.domain_name",        # Option 15
        "dhcp.option.hostname",           # Option 12
        "dhcp.option.router",             # Option 3
        "dhcp.option.dhcp_server_id",     # Option 54
    ]

    # Оставляем только валидные поля (чтобы tshark не падал)
    ok_fields: List[str] = []
    for f in fields:
        cmd_test = [tshark, "-r", str(PCAP_PATH), "-Y", "bootp || dhcp", "-T", "fields", "-e", f, "-c", "1"]
        code, _, err = run_cmd(cmd_test)
        if code == 0 and "Some fields aren't valid" not in err:
            ok_fields.append(f)

    df = tshark_tsv(tshark, "bootp || dhcp", ok_fields)
    if df.empty:
        return df

    rename = {
        "frame.number": "frame_no",
        "frame.time_epoch": "time_epoch",
        "ip.src": "src_ip",
        "ip.dst": "dst_ip",
        "eth.src": "client_mac",
        "bootp.yiaddr": "assigned_ip",
        "bootp.siaddr": "server_ip",
        "bootp.option.dhcp": "dhcp_type_raw",
        "dhcp.option.domain_name_server": "dhcp_dns_servers",
        "dhcp.option.domain_name": "dhcp_domain_name",
        "dhcp.option.hostname": "hostname",
        "dhcp.option.router": "dhcp_router",
        "dhcp.option.dhcp_server_id": "dhcp_server_id",
    }
    df.rename(columns={k: v for k, v in rename.items() if k in df.columns}, inplace=True)

    # Гарантируем колонки
    for col in [
        "frame_no", "time_epoch", "src_ip", "dst_ip", "client_mac",
        "assigned_ip", "server_ip", "dhcp_type_raw",
        "dhcp_dns_servers", "dhcp_domain_name", "hostname",
        "dhcp_router", "dhcp_server_id"
    ]:
        if col not in df.columns:
            df[col] = ""

    # Время
    df["time_epoch"] = pd.to_numeric(df.get("time_epoch"), errors="coerce")
    df["time"] = pd.to_datetime(df["time_epoch"], unit="s", errors="coerce")

    # 1) Сначала пробуем маппинг по raw (если вдруг это реально цифра)
    df["dhcp_type_raw"] = df["dhcp_type_raw"].astype(str).str.strip()
    df["dhcp_type"] = df["dhcp_type_raw"].map(DHCP_TYPE_MAP).fillna(df["dhcp_type_raw"])
    df.loc[df["dhcp_type"].astype(str).str.len() == 0, "dhcp_type"] = "Unknown"

    # 2) Если всё равно Unknown — берём типы из verbose (-V), как в Wireshark
    if (df["dhcp_type"].astype(str) == "Unknown").all():
        mapping = dhcp_types_from_verbose(tshark)
        if mapping:
            df["frame_no"] = pd.to_numeric(df["frame_no"], errors="coerce")
            df["dhcp_type"] = df["frame_no"].apply(
                lambda n: mapping.get(int(n), "Unknown") if pd.notna(n) else "Unknown"
            )

    # server_ip: если пусто, подставим dhcp_server_id (Option 54)
    df["server_ip"] = df["server_ip"].where(df["server_ip"].astype(str).str.strip().ne(""), df["dhcp_server_id"])

    return df


# -----------------------------
# Артефакты: IP endpoints (src/dst)
# -----------------------------
def extract_ip_endpoints(tshark: str) -> pd.DataFrame:
    df = tshark_tsv(tshark, "ip", ["frame.time_epoch", "ip.src", "ip.dst"])
    if df.empty:
        return df
    df.rename(columns={
        "frame.time_epoch": "time_epoch",
        "ip.src": "src_ip",
        "ip.dst": "dst_ip",
    }, inplace=True)
    df["time_epoch"] = pd.to_numeric(df["time_epoch"], errors="coerce")
    df["time"] = pd.to_datetime(df["time_epoch"], unit="s", errors="coerce")
    return df


def save_report(dns_df: pd.DataFrame, ip_df: pd.DataFrame, dhcp_df: pd.DataFrame) -> None:
    lines = []
    lines.append("Краткий отчёт по анализу сетевого дампа (PCAP)\n")
    lines.append(f"Источник данных: {PCAP_PATH.name}")
    lines.append("Метод: tshark -> pandas -> базовая аналитика + визуализация\n")

    lines.append("Артефакты:")
    lines.append(f"- IP endpoints (ip.src/ip.dst): {len(ip_df)} пакетов")
    if not ip_df.empty:
        uniq_ips = pd.unique(pd.concat([ip_df["src_ip"], ip_df["dst_ip"]], ignore_index=True).dropna())
        uniq_ips = [x for x in uniq_ips if str(x).strip()]
        lines.append(f"  Уникальных IP (src+dst): {len(uniq_ips)}")

    lines.append(f"- DHCP/BOOTP events: {len(dhcp_df)} пакетов")
    if not dhcp_df.empty and "dhcp_type" in dhcp_df.columns:
        lines.append(f"  DHCP types: {dhcp_df['dhcp_type'].value_counts().to_dict()}")

        # DNS-настройки из DHCP Option 6 
        dns_opt = dhcp_df["dhcp_dns_servers"].astype(str).str.strip()
        dns_opt = dns_opt[(dns_opt != "") & (dns_opt.str.lower() != "nan")].unique().tolist()
        if dns_opt:
            lines.append(f"  DHCP Option 6 (DNS servers) найдено: {dns_opt}")
        else:
            lines.append("  DHCP Option 6 (DNS servers): не обнаружено/не извлечено")

        # Assigned IP
        assigned = dhcp_df["assigned_ip"].astype(str).str.strip()
        assigned = assigned[(assigned != "") & (assigned.str.lower() != "nan")].unique().tolist()
        if assigned:
            lines.append(f"  Выданные IP (assigned_ip): {assigned}")

        # Server IP
        srv = dhcp_df["server_ip"].astype(str).str.strip()
        srv = srv[(srv != "") & (srv.str.lower() != "nan")].unique().tolist()
        if srv:
            lines.append(f"  DHCP server IP (server_ip): {srv}")

    lines.append(f"- DNS queries (dns.qry.name): {len(dns_df)}")
    if dns_df.empty:
        lines.append("  DNS queries не обнаружены в дампе (это тоже результат анализа).")
        lines.append("  Возможные причины: трафик DNS отсутствует/обрезан/использовались DoH/DoT.")
    else:
        top = dns_df["domain"].value_counts().head(5).to_dict()
        lines.append(f"  Top domains: {top}")

    lines.append("\nРекомендации:")
    lines.append("- Если нужна именно DNS активность: проверить наличие DoH/DoT (HTTPS/TLS), SNI, QUIC.")
    lines.append("- Проверить выданные IP (assigned_ip), MAC и hostname из DHCP на соответствие ожидаемым хостам.")
    lines.append("- При необходимости — запросить более полный PCAP (не только DHCP).")

    (REPORT_DIR / "summary.txt").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    if not PCAP_PATH.exists():
        raise FileNotFoundError(f"Не найден файл дампа: {PCAP_PATH}")

    tshark = require_tshark()

    # 1) IP endpoints
    ip_df = extract_ip_endpoints(tshark)
    ip_df.to_csv(ARTIFACTS_DIR / "ip_endpoints.csv", index=False)

    # 2) DHCP events
    dhcp_df = extract_dhcp(tshark)
    dhcp_df.to_csv(ARTIFACTS_DIR / "dhcp_events.csv", index=False)

    # 3) DNS queries
    dns_df = extract_dns_queries(tshark)
    dns_df.to_csv(ARTIFACTS_DIR / "dns_requests.csv", index=False)

    # ---- Визуализации ----

    # DHCP по типам
    if not dhcp_df.empty and "dhcp_type" in dhcp_df.columns:
        plt.figure()
        dhcp_df["dhcp_type"].fillna("Unknown").value_counts().plot(kind="bar")
        plt.title("DHCP message types (counts)")
        plt.xlabel("Message type")
        plt.ylabel("Count")
        plt.tight_layout()
        plt.savefig(OUTPUTS_DIR / "dhcp_message_types.png", dpi=200)
        plt.close()

    # DNS по времени + top domains (если есть)
    if not dns_df.empty and dns_df["time"].notna().any():
        d = dns_df.dropna(subset=["time"]).copy()
        d["minute"] = d["time"].dt.floor("min")
        series = d.groupby("minute").size()

        plt.figure()
        series.plot()
        plt.xlabel("Время")
        plt.ylabel("Количество DNS-запросов")
        plt.title("DNS-запросы по времени")
        plt.tight_layout()
        plt.savefig(OUTPUTS_DIR / "dns_over_time.png", dpi=200)
        plt.close()

        top = d["domain"].value_counts().head(10)
        plt.figure()
        top.plot(kind="bar")
        plt.xlabel("Домен")
        plt.ylabel("Количество")
        plt.title("Top-10 доменов по частоте DNS-запросов")
        plt.tight_layout()
        plt.savefig(OUTPUTS_DIR / "top_domains.png", dpi=200)
        plt.close()

    # IP talkers (топ источников)
    if not ip_df.empty and "src_ip" in ip_df.columns:
        top_src = ip_df["src_ip"].astype(str).str.strip()
        top_src = top_src[top_src != ""].value_counts().head(10)
        if not top_src.empty:
            plt.figure()
            top_src.plot(kind="bar")
            plt.xlabel("Source IP")
            plt.ylabel("Packets")
            plt.title("Top-10 source IPs (by packets)")
            plt.tight_layout()
            plt.savefig(OUTPUTS_DIR / "top_source_ips.png", dpi=200)
            plt.close()

    # 4) Отчёт
    save_report(dns_df, ip_df, dhcp_df)

    print("OK:")
    print("  artifacts ->", ARTIFACTS_DIR)
    print("  outputs   ->", OUTPUTS_DIR)
    print("  report    ->", REPORT_DIR)
    print("  DNS rows  ->", len(dns_df))
    print("  IP rows   ->", len(ip_df))
    print("  DHCP rows ->", len(dhcp_df))
    if not dhcp_df.empty and "dhcp_type" in dhcp_df.columns:
        print("  DHCP type counts ->", dhcp_df["dhcp_type"].value_counts().to_dict())


if __name__ == "__main__":
    main()