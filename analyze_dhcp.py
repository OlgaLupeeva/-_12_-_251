
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from collections import defaultdict
import json
import os

class DHCPAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.dhcp_events = []
        self.dhcp_leases = []
        self.cap = None
        
    def load_capture(self):
        """Загрузка pcap файла"""
        print(f"[+] Загрузка файла: {self.pcap_file}")
        self.cap = pyshark.FileCapture(
            self.pcap_file, 
            display_filter='bootp',
            use_json=True
        )
        print(f"[+] Файл успешно загружен")
        
    def extract_dhcp_events(self):
        """Извлечение DHCP событий"""
        print("\n[+] Извлечение DHCP событий...")
        
        dhcp_message_types = {
            '1': 'DISCOVER',
            '2': 'OFFER',
            '3': 'REQUEST',
            '4': 'DECLINE',
            '5': 'ACK',
            '6': 'NAK',
            '7': 'RELEASE',
            '8': 'INFORM'
        }
        
        for packet in self.cap:
            try:
                if 'BOOTP' in packet:
                    bootp = packet.bootp
                    
                    # Определение типа DHCP сообщения
                    dhcp_option = bootp.get_field_value('dhcp_message_type')
                    message_type = dhcp_message_types.get(dhcp_option, 'UNKNOWN')
                    
                    event = {
                        'timestamp': packet.sniff_time,
                        'source_ip': packet.ip.src if hasattr(packet, 'ip') else '0.0.0.0',
                        'dest_ip': packet.ip.dst if hasattr(packet, 'ip') else '255.255.255.255',
                        'source_mac': bootp.chaddr,
                        'client_ip': bootp.ciaddr,
                        'your_ip': bootp.yiaddr,
                        'server_ip': bootp.siaddr,
                        'message_type': message_type,
                        'transaction_id': bootp.id,
                        'lease_time': None
                    }
                    
                    # Извлечение времени аренды (option 51)
                    if hasattr(bootp, 'dhcp_option_51'):
                        event['lease_time'] = bootp.dhcp_option_51
                    
                    # Извлечение subnet mask (option 1)
                    if hasattr(bootp, 'dhcp_option_subnet_mask'):
                        event['subnet_mask'] = bootp.dhcp_option_subnet_mask
                    else:
                        event['subnet_mask'] = None
                    
                    # Извлечение router (option 3)
                    if hasattr(bootp, 'dhcp_option_router'):
                        event['router'] = bootp.dhcp_option_router
                    else:
                        event['router'] = None
                    
                    # Извлечение DNS server (option 6)
                    if hasattr(bootp, 'dhcp_option_domain_name_server'):
                        event['dns_server'] = bootp.dhcp_option_domain_name_server
                    else:
                        event['dns_server'] = None
                    
                    self.dhcp_events.append(event)
                    
            except Exception as e:
                print(f"[-] Ошибка при обработке пакета: {e}")
                continue
        
        print(f"[+] Извлечено событий: {len(self.dhcp_events)}")
        return self.dhcp_events
    
    def extract_leases(self):
        """Извлечение информации о DHCP арендах"""
        print("\n[+] Анализ DHCP аренд...")
        
        # Группировка по MAC-адресам для отслеживания полных DORA процессов
        mac_transactions = defaultdict(list)
        
        for event in self.dhcp_events:
            mac = event['source_mac']
            mac_transactions[mac].append(event)
        
        # Анализ полных процессов получения адреса
        for mac, events in mac_transactions.items():
            discover = None
            offer = None
            request = None
            ack = None
            
            for event in events:
                msg_type = event['message_type']
                if msg_type == 'DISCOVER':
                    discover = event
                elif msg_type == 'OFFER':
                    offer = event
                elif msg_type == 'REQUEST':
                    request = event
                elif msg_type == 'ACK':
                    ack = event
            
            # Если есть полная последовательность DORA
            if discover and offer and request and ack:
                lease_info = {
                    'mac_address': mac,
                    'assigned_ip': ack['your_ip'],
                    'server_ip': ack['server_ip'],
                    'lease_time': ack.get('lease_time'),
                    'subnet_mask': ack.get('subnet_mask'),
                    'router': ack.get('router'),
                    'dns_server': ack.get('dns_server'),
                    'discover_time': discover['timestamp'],
                    'offer_time': offer['timestamp'],
                    'request_time': request['timestamp'],
                    'ack_time': ack['timestamp'],
                    'total_time_seconds': (ack['timestamp'] - discover['timestamp']).total_seconds()
                }
                self.dhcp_leases.append(lease_info)
        
        print(f"[+] Найдено аренд: {len(self.dhcp_leases)}")
        return self.dhcp_leases
    
    def save_artifacts(self, artifacts_dir='artifacts'):
        """Сохранение артефактов в CSV файлы"""
        print(f"\n[+] Сохранение артефактов в {artifacts_dir}/")
        
        os.makedirs(artifacts_dir, exist_ok=True)
        
        # Сохранение DHCP событий
        events_df = pd.DataFrame(self.dhcp_events)
        events_file = os.path.join(artifacts_dir, 'dhcp_events.csv')
        events_df.to_csv(events_file, index=False, encoding='utf-8')
        print(f"[+] Сохранено событий: {events_file}")
        
        # Сохранение DHCP аренд
        leases_df = pd.DataFrame(self.dhcp_leases)
        leases_file = os.path.join(artifacts_dir, 'dhcp_leases.csv')
        leases_df.to_csv(leases_file, index=False, encoding='utf-8')
        print(f"[+] Сохранено аренд: {leases_file}")
        
        return events_df, leases_df
    
    def create_visualizations(self, outputs_dir='outputs'):
        """Создание визуализаций"""
        print(f"\n[+] Создание визуализаций в {outputs_dir}/")
        
        os.makedirs(outputs_dir, exist_ok=True)
        
        # Настройка стиля
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = [12, 6]
        plt.rcParams['font.size'] = 10
        
        # 1. График DHCP сообщений по времени
        fig1, ax1 = plt.subplots()
        
        if self.dhcp_events:
            df_events = pd.DataFrame(self.dhcp_events)
            df_events['timestamp'] = pd.to_datetime(df_events['timestamp'])
            df_events['minute'] = df_events['timestamp'].dt.floor('T')
            
            messages_per_minute = df_events.groupby(['minute', 'message_type']).size().unstack(fill_value=0)
            
            if not messages_per_minute.empty:
                messages_per_minute.plot(kind='bar', stacked=True, ax=ax1, colormap='viridis')
                ax1.set_xlabel('Время')
                ax1.set_ylabel('Количество сообщений')
                ax1.set_title('DHCP сообщения по времени')
                ax1.legend(title='Тип сообщения', bbox_to_anchor=(1.05, 1), loc='upper left')
                plt.xticks(rotation=45)
                plt.tight_layout()
        
        output1 = os.path.join(outputs_dir, 'dhcp_messages_over_time.png')
        plt.savefig(output1, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"[+] Сохранен график: {output1}")
        
        # 2. График распределения типов DHCP сообщений
        fig2, ax2 = plt.subplots()
        
        if self.dhcp_events:
            df_events = pd.DataFrame(self.dhcp_events)
            message_counts = df_events['message_type'].value_counts()
            
            colors = plt.cm.Set3(range(len(message_counts)))
            wedges, texts, autotexts = ax2.pie(
                message_counts.values, 
                labels=message_counts.index, 
                autopct='%1.1f%%',
                colors=colors,
                startangle=90
            )
            
            # Улучшение читаемости
            plt.setp(autotexts, size=10, weight="bold")
            ax2.set_title('Распределение типов DHCP сообщений')
        
        output2 = os.path.join(outputs_dir, 'dhcp_message_types.png')
        plt.savefig(output2, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"[+] Сохранен график: {output2}")
        
        # 3. Дополнительная статистика
        if self.dhcp_leases:
            df_leases = pd.DataFrame(self.dhcp_leases)
            
            fig3, axes = plt.subplots(1, 2, figsize=(14, 5))
            
            # Распределение времени аренды
            if 'lease_time' in df_leases.columns and df_leases['lease_time'].notna().any():
                axes[0].hist(df_leases['lease_time'].dropna(), bins=20, color='skyblue', edgecolor='black')
                axes[0].set_xlabel('Время аренды (секунды)')
                axes[0].set_ylabel('Количество')
                axes[0].set_title('Распределение времени аренды DHCP')
            
            # Время получения адреса
            if 'total_time_seconds' in df_leases.columns:
                axes[1].hist(df_leases['total_time_seconds'], bins=20, color='lightgreen', edgecolor='black')
                axes[1].set_xlabel('Время получения адреса (секунды)')
                axes[1].set_ylabel('Количество')
                axes[1].set_title('Время завершения DORA процесса')
            
            plt.tight_layout()
            output3 = os.path.join(outputs_dir, 'dhcp_statistics.png')
            plt.savefig(output3, dpi=300, bbox_inches='tight')
            plt.close()
            print(f"[+] Сохранен график: {output3}")
    
    def generate_report(self):
        """Генерация отчета по анализу"""
        print("\n" + "="*60)
        print("ОТЧЕТ ПО АНАЛИЗУ DHCP ТРАФИКА")
        print("="*60)
        
        print(f"\n1. ОБЩАЯ СТАТИСТИКА:")
        print(f"   - Всего DHCP сообщений: {len(self.dhcp_events)}")
        print(f"   - Всего аренд (полных DORA): {len(self.dhcp_leases)}")
        
        if self.dhcp_events:
            df_events = pd.DataFrame(self.dhcp_events)
            print(f"\n2. РАСПРЕДЕЛЕНИЕ ТИПОВ СООБЩЕНИЙ:")
            for msg_type, count in df_events['message_type'].value_counts().items():
                print(f"   - {msg_type}: {count} ({count/len(df_events)*100:.1f}%)")
            
            print(f"\n3. УНИКАЛЬНЫЕ DHCP СЕРВЕРЫ:")
            servers = df_events[df_events['server_ip'] != '0.0.0.0']['server_ip'].unique()
            for server in servers:
                count = len(df_events[df_events['server_ip'] == server])
                print(f"   - {server}: {count} сообщений")
            
            print(f"\n4. УНИКАЛЬНЫЕ КЛИЕНТЫ (по MAC):")
            unique_macs = df_events['source_mac'].nunique()
            print(f"   - Всего уникальных клиентов: {unique_macs}")
            
            # Топ клиентов по активности
            top_clients = df_events['source_mac'].value_counts().head(5)
            print(f"\n5. ТОП-5 АКТИВНЫХ КЛИЕНТОВ:")
            for i, (mac, count) in enumerate(top_clients.items(), 1):
                print(f"   {i}. {mac}: {count} сообщений")
        
        if self.dhcp_leases:
            df_leases = pd.DataFrame(self.dhcp_leases)
            print(f"\n6. ИНФОРМАЦИЯ ОБ АРЕНДАХ:")
            
            if 'assigned_ip' in df_leases.columns:
                unique_ips = df_leases['assigned_ip'].nunique()
                print(f"   - Выдано уникальных IP: {unique_ips}")
            
            if 'lease_time' in df_leases.columns and df_leases['lease_time'].notna().any():
                avg_lease = df_leases['lease_time'].mean()
                print(f"   - Среднее время аренды: {avg_lease:.0f} сек ({avg_lease/3600:.1f} час)")
            
            if 'total_time_seconds' in df_leases.columns:
                avg_dora_time = df_leases['total_time_seconds'].mean()
                max_dora_time = df_leases['total_time_seconds'].max()
                print(f"   - Среднее время DORA процесса: {avg_dora_time:.3f} сек")
                print(f"   - Максимальное время DORA: {max_dora_time:.3f} сек")
        
        print("\n" + "="*60)
        print("ВЫВОДЫ:")
        print("="*60)
        
        # Анализ на аномалии
        anomalies = []
        
        if self.dhcp_events:
            df_events = pd.DataFrame(self.dhcp_events)
            
            # Проверка на множественные DHCP серверы
            servers = df_events[df_events['server_ip'] != '0.0.0.0']['server_ip'].unique()
            if len(servers) > 1:
                anomalies.append(f"⚠️  Обнаружено {len(servers)} DHCP серверов (возможна rogue DHCP атака)")
            
            # Проверка на большое количество NAK
            nak_count = len(df_events[df_events['message_type'] == 'NAK'])
            if nak_count > 0:
                anomalies.append(f"⚠️  Обнаружено {nak_count} NAK сообщений (ошибки выделения адресов)")
            
            # Проверка на DECLINE
            decline_count = len(df_events[df_events['message_type'] == 'DECLINE'])
            if decline_count > 0:
                anomalies.append(f"⚠️  Обнаружено {decline_count} DECLINE сообщений (конфликты IP адресов)")
        
        if not anomalies:
            print("✓ Аномалий не обнаружено")
        else:
            for anomaly in anomalies:
                print(anomaly)
        
        print("\n" + "="*60)
    
    def analyze(self):
        """Полный анализ DHCP трафика"""
        self.load_capture()
        self.extract_dhcp_events()
        self.extract_leases()
        self.save_artifacts()
        self.create_visualizations()
        self.generate_report()
        
        print("\n[+] Анализ завершен успешно!")


def main():
    """Основная функция"""
    # Путь к pcap файлу
    pcap_file = 'data/dhcp.pcapng'
    
    # Проверка существования файла
    if not os.path.exists(pcap_file):
        print(f"[-] Ошибка: файл {pcap_file} не найден!")
        print("    Поместите файл dhcp.pcapng в папку data/")
        return
    
    # Создание анализатора и запуск анализа
    analyzer = DHCPAnalyzer(pcap_file)
    analyzer.analyze()


if __name__ == "__main__":
    main()
