# ДЗ-12 — Python для аналитиков ИБ: форензика (сетевой дамп DHCP)

## Что сделано
- Проанализирован сетевой дамп `dhcp.pcapng` с помощью `pyshark`
- Извлечены ключевые артефакты DHCP:
  - типы сообщений (Discover/Offer/Request/ACK/NAK)
  - MAC-адреса клиентов
  - выданные IP (yiaddr), запрошенные IP (Option 50)
  - hostname (Option 12), server id/router/dns (если присутствуют)
- Сформированы артефакты:
  - `artifacts/dhcp_events.csv` — полный лог событий
  - `artifacts/dhcp_leases.csv` — итоговая таблица аренды (MAC → IP)
- Построены визуализации:
  - `outputs/dhcp_message_types.png`
  - `outputs/dhcp_messages_over_time.png`

## Как запустить
```bash
pip install -r requirements.txt
python src/analyze_dhcp.py
