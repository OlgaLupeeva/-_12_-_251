import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ===== 1. Название дампа =====
dump_file = "dhcp.pcapng"

# ===== 2. Загрузка дампа =====
capture = pyshark.FileCapture(dump_file)

data = []

# ===== 3. Извлечение DNS и IP событий =====
for packet in capture:
    try:
        timestamp = packet.sniff_time
        
        # DNS события
        if 'DNS' in packet:
            data.append({
                "time": timestamp,
                "type": "DNS",
                "src_ip": packet.ip.src,
                "dst_ip": packet.ip.dst
            })
        
        # DHCP события (так как файл dhcp)
        elif 'DHCP' in packet:
            data.append({
                "time": timestamp,
                "type": "DHCP",
                "src_ip": packet.ip.src if hasattr(packet, 'ip') else "N/A",
                "dst_ip": packet.ip.dst if hasattr(packet, 'ip') else "N/A"
            })

    except AttributeError:
        continue

capture.close()

# ===== 4. DataFrame =====
df = pd.DataFrame(data)

# Перевод времени в datetime
df['time'] = pd.to_datetime(df['time'])

# Группировка по минутам
df['minute'] = df['time'].dt.floor('T')

# ===== 5. ГРАФИК 1 — Количество событий по времени =====
events_by_time = df.groupby('minute').size().reset_index(name='count')

plt.figure()
plt.plot(events_by_time['minute'], events_by_time['count'])
plt.title(f"Количество сетевых событий по времени\nДамп: {dump_file}")
plt.xlabel("Время")
plt.ylabel("Количество событий")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()


# ===== 6. ГРАФИК 2 — Типы событий по времени =====
events_by_type = df.groupby(['minute', 'type']).size().reset_index(name='count')

plt.figure()
for event_type in events_by_type['type'].unique():
    subset = events_by_type[events_by_type['type'] == event_type]
    plt.plot(subset['minute'], subset['count'], label=event_type)

plt.title(f"Типы событий по времени\nДамп: {dump_file}")
plt.xlabel("Время")
plt.ylabel("Количество событий")
plt.legend()
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()
