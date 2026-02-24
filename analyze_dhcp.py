
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from collections import defaultdict
import json
import os
import asyncio

# Исправление для asyncio в Python 3.10+
try:
    asyncio.set_event_loop(asyncio.new_event_loop())
except Exception as e:
    print(f"[!] Warning: {e}")

class DHCPAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.dhcp_events = []
        self.dhcp_leases = []
        self.cap = None
        
    def load_capture(self):
        """Загрузка pcap файла"""
        print(f"[+] Загрузка файла: {self.pcap_file}")
        
        # Исправленная версия без use_json
        self.cap = pyshark.FileCapture(
            self.pcap_file, 
            display_filter='bootp',
            only_summaries=False,
            keep_packets=False
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
        
        packet_count = 0
        
        for packet in self.cap:
            try:
                if hasattr(packet, 'bootp'):
                    bootp = packet.bootp
                    
                    # Определение типа DHCP сообщения
                    msg_type_field = bootp.get_field_value('dhcp_message_type')
                    message_type = dhcp_message_types.get(msg_type_field, 'UNKNOWN')
                    
                    # Получение IP адресов
                    src_ip = packet.ip.src if hasattr(packet, 'ip') else '0.0.0.0'
                    dst_ip = packet.ip.dst if hasattr(packet, 'ip') else '255.255.255.255'
                    
                    # Получение MAC адреса
                    chaddr = bootp.chaddr if hasattr(bootp, 'chaddr') else ''
                    
                    # Получение IP адресов из BOOTP
                    ciaddr = bootp.ciaddr if hasattr(bootp, 'ciaddr') else '0.0.0.0'
                    yiaddr = bootp.yiaddr if hasattr(bootp, 'yiaddr') else '0.0.0.0'
                    siaddr = bootp.siaddr if hasattr(bootp, 'siaddr') else '0.0.0.0'
                    
                    # Получение transaction ID
                    trans_id = bootp.id if hasattr(bootp, 'id') else '0'
                    
                    event = {
                        'timestamp': packet.sniff_time,
                        'source_ip': src_ip,
                        'dest_ip': dst_ip,
                        'source_mac': chaddr,
                        'client_ip': ciaddr,
                        'your_ip': yiaddr,
                        'server_ip': siaddr,
                        'message_type': message_type,
                        'transaction_id': trans_id,
                        'lease_time': None,
                        'subnet_mask': None,
                        'router': None,
                        'dns_server': None
                    }
                    
                    # Извлечение опций DHCP (если доступны)
                    if hasattr(bootp, 'dhcp_options'):
                        options = bootp.dhcp_options
                        
                        # Поиск времени аренды (option 51)
                        if 'dhcp_option_51' in str(options):
                            try:
                                event['lease_time'] = bootp.dhcp_option_51
                            except:
                                pass
                        
                        # Поиск subnet mask (option 1)
                        if 'dhcp_option_subnet_mask' in str(options):
                            try:
                                event['subnet_mask'] = bootp.dhcp_option_subnet_mask
                            except:
                                pass
                        
                        # Поиск router (option 3)
                        if 'dhcp_option_router' in str(options):
                            try:
                                event['router'] = bootp.dhcp_option_router
                            except:
                                pass
                        
                        # Поиск DNS server (option 6)
                        if 'dhcp_option_domain_name_server' in str(options):
                            try:
                                event['dns_server'] = bootp.dhcp_option_domain_name_server
                            except:
                                pass
                    
                    self.dhcp_events.append(event)
                    packet_count += 1
                    
            except Exception as e:
                # Пропускаем пакеты с ошибками
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
                try:
                    total_time = (ack['timestamp'] - discover['timestamp']).total_seconds()
                except:
                    total_time = 0
                
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
                    'total_time_seconds': total_time
                }
                self.dhcp_leases.append(lease_info)
        
        print(f"[+] Найдено аренд: {len(self.dhcp_leases)}")
        return self.dhcp_leases
    
    def save_artifacts(self, artifacts_dir='artifacts'):
        """Сохранение артефактов в CSV файлы"""
        print(f"\n[+] Сохранение артефактов в {artifacts_dir}/")
        
        os.makedirs(artifacts_dir, exist_ok=True)
        
        # Сохранение DHCP событий
        if self.dhcp_events:
            events_df = pd.DataFrame(self.dhcp_events)
            events_file = os.path.join(artifacts_dir, 'dhcp_events.csv')
            events_df.to_csv(events_file, index=False, encoding='utf-8')
            print(f"[+] Сохранено событий: {events_file}")
        else:
            print("[-] Нет событий для сохранения")
        
        # Сохранение DHCP аренд
        if self.dhcp_leases:
            leases_df = pd.DataFrame(self.dhcp_leases)
            leases_file = os.path.join(artifacts_dir, 'dhcp_leases.csv')
            leases_df.to_csv(leases_file, index=False, encoding='utf-8')
            print(f"[+] Сохранено аренд: {leases_file}")
        else:
            print("[-] Нет аренд для сохранения")
    
    def create_visualizations(self, outputs_dir='outputs'):
        """Создание визуализаций"""
        print(f"\n[+] Создание визуализаций в {outputs_dir}/")
        
        os.makedirs(outputs_dir, exist_ok=True)
        
        # Настройка стиля
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = [12, 6]
        plt.rcParams['font.size'] = 10
        
        if not self.dhcp_events:
            print("[-] Нет данных для визуализации")
            return
        
        df_events = pd.DataFrame(self.dhcp_events)
        
        # 1. График DHCP сообщений по времени
        fig1, ax1 = plt.subplots()
        
        try:
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
        except Exception as e:
            print(f"[-] Ошибка при создании графика 1: {e}")
            ax1.text(0.5, 0.5, 'Нет данных для отображения', ha='center', va='center')
        
        output1 = os.path.join(outputs_dir, 'dhcp_messages_over_time.png')
        plt.savefig(output1, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"[+] Сохранен график: {output1}")
        
        # 2. График распределения типов DHCP сообщений
        fig2, ax2 = plt.subplots()
        
        message_counts = df_events['message_type'].value_counts()
        
        if len(message_counts) > 0:
            colors = plt.cm.Set3(range(len(message_counts)))
            wedges, texts, autotexts = ax2.pie(
                message_counts.values, 
                labels=message_counts.index, 
                autopct='%1.1f%%',
                colors=colors,
                startangle=90
            )
            plt.setp(autotexts, size=10, weight="bold")
            ax2.set_title('Распределение типов DHCP сообщений')
        else:
            ax2.text(0.5, 0.5, 'Нет данных', ha='center', va='center')
        
        output2 = os.path.join(outputs_dir, 'dhcp_message_types.png')
        plt.savefig(output2, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"[+] Сохранен график: {output2}")
        
        # 3. Дополнительная статистика (если есть аренды)
        if self.dhcp_leases:
            df_leases = pd.DataFrame(self.dhcp_leases)
            
            fig3, axes = plt.subplots(1, 2, figsize=(14, 5))
            
            # Распределение времени аренды
            if 'lease_time' in df_leases.columns:
                lease_times = df_leases['lease_time'].dropna()
                if len(lease_times) > 0:
                    try:
                        lease_times_numeric = pd.to_numeric(lease_times, errors='coerce').dropna()
                        if len(lease_times_numeric) > 0:
                            axes[0].hist(lease_times_numeric, bins=20, color='skyblue', edgecolor='black')
                            axes[0].set_xlabel('Время аренды (секунды)')
                            axes[0].set_ylabel('Количество')
                            axes[0].set_title('Распределение времени аренды DHCP')
                    except:
                        axes[0].text(0.5, 0.5, 'Нет данных', ha='center', va='center')
                else:
                    axes[0].text(0.5, 0.5, 'Нет данных', ha='center', va='center')
            
            # Время получения адреса
            if 'total_time_seconds' in df_leases.columns:
                total_times = df_leases['total_time_seconds'].dropna()
                if len(total_times) > 0:
                    axes[1].hist(total_times, bins=20, color='lightgreen', edgecolor='black')
                    axes[1].set_xlabel('Время получения адреса (секунды)')
                    axes[1].set_ylabel('Количество')
                    axes[1].set_title('Время завершения DORA процесса')
                else:
                    axes[1].text(0.5, 0.5, 'Нет данных', ha='center', va='center')
            
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
            
            if 'lease_time' in df_leases.columns:
                lease_times = pd.to_numeric(df_leases['lease_time'], errors='coerce').dropna()
                if len(lease_times) > 0:
                    avg_lease = lease_times.mean()
                    print(f"   - Среднее время аренды: {avg_lease:.0f} сек ({avg_lease/3600:.1f} час)")
            
            if 'total_time_seconds' in df_leases.columns:
                total_times = df_leases['total_time_seconds'].dropna()
                if len(total_times) > 0:
                    avg_dora_time = total_times.mean()
                    max_dora_time = total_times.max()
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
