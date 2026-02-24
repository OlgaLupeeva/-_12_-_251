import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from collections import defaultdict
import os
import sys

# Добавляем обработку asyncio для Windows
if sys.platform == 'win32':
    import asyncio
    asyncio.set_event_loop(asyncio.ProactorEventLoop())

class DHCPAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.dhcp_events = []
        self.dhcp_leases = []
        
    def load_and_analyze(self):
        """Загрузка и анализ pcap файла"""
        print(f"[+] Загрузка файла: {self.pcap_file}")
        
        if not os.path.exists(self.pcap_file):
            print(f"[-] Ошибка: файл {self.pcap_file} не найден!")
            return False
        
        try:
            # Используем простой фильтр для DHCP
            cap = pyshark.FileCapture(
                self.pcap_file,
                display_filter='dhcp',
                use_json=False,
                keep_packets=False
            )
            
            print(f"[+] Анализ пакетов...")
            packet_num = 0
            
            for packet in cap:
                packet_num += 1
                
                # Проверяем наличие DHCP слоя
                if hasattr(packet, 'dhcp'):
                    self.process_dhcp_packet(packet, packet_num)
                elif hasattr(packet, 'bootp'):
                    self.process_bootp_packet(packet, packet_num)
                elif 'DHCP' in str(packet):
                    # Пробуем извлечь информацию даже если нет явного слоя
                    self.process_generic_packet(packet, packet_num)
            
            cap.close()
            
            print(f"[+] Всего обработано пакетов: {packet_num}")
            print(f"[+] Найдено DHCP событий: {len(self.dhcp_events)}")
            
            return True
            
        except Exception as e:
            print(f"[-] Ошибка при загрузке: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def process_dhcp_packet(self, packet, num):
        """Обработка DHCP пакета"""
        try:
            dhcp = packet.dhcp
            
            # Получаем тип DHCP сообщения
            msg_type = "UNKNOWN"
            if hasattr(dhcp, 'dhcp_message_type'):
                type_map = {
                    '1': 'DISCOVER',
                    '2': 'OFFER', 
                    '3': 'REQUEST',
                    '4': 'DECLINE',
                    '5': 'ACK',
                    '6': 'NAK',
                    '7': 'RELEASE',
                    '8': 'INFORM'
                }
                msg_type = type_map.get(str(dhcp.dhcp_message_type), 'UNKNOWN')
            
            # Извлекаем IP адреса
            src_ip = packet.ip.src if hasattr(packet, 'ip') else '0.0.0.0'
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else '255.255.255.255'
            
            # Извлекаем BOOTP поля если есть
            ciaddr = '0.0.0.0'
            yiaddr = '0.0.0.0' 
            siaddr = '0.0.0.0'
            chaddr = ''
            xid = '0'
            
            if hasattr(packet, 'bootp'):
                bootp = packet.bootp
                ciaddr = getattr(bootp, 'ciaddr', '0.0.0.0')
                yiaddr = getattr(bootp, 'yiaddr', '0.0.0.0')
                siaddr = getattr(bootp, 'siaddr', '0.0.0.0')
                chaddr = getattr(bootp, 'chaddr', '')
                xid = getattr(bootp, 'id', '0')
            
            event = {
                'packet_number': num,
                'timestamp': packet.sniff_time,
                'source_ip': src_ip,
                'dest_ip': dst_ip,
                'source_mac': chaddr,
                'client_ip': ciaddr,
                'your_ip': yiaddr,
                'server_ip': siaddr,
                'message_type': msg_type,
                'transaction_id': xid,
                'lease_time': None
            }
            
            # Пробуем получить время аренды
            if hasattr(dhcp, 'dhcp_lease_time'):
                event['lease_time'] = dhcp.dhcp_lease_time
            
            self.dhcp_events.append(event)
            print(f"    [Пакет {num}] {msg_type} - {src_ip} -> {dst_ip}")
            
        except Exception as e:
            print(f"[-] Ошибка обработки DHCP пакета {num}: {e}")
    
    def process_bootp_packet(self, packet, num):
        """Обработка BOOTP пакета"""
        try:
            bootp = packet.bootp
            
            # Определяем тип сообщения по opcode
            opcode = getattr(bootp, 'opcode', '1')
            msg_type = 'BOOTP_REQUEST' if str(opcode) == '1' else 'BOOTP_REPLY'
            
            # Если есть DHCP опции, определяем тип
            if hasattr(bootp, 'dhcp_message_type'):
                type_map = {
                    '1': 'DISCOVER',
                    '2': 'OFFER',
                    '3': 'REQUEST', 
                    '4': 'DECLINE',
                    '5': 'ACK',
                    '6': 'NAK',
                    '7': 'RELEASE',
                    '8': 'INFORM'
                }
                msg_type = type_map.get(str(bootp.dhcp_message_type), msg_type)
            
            event = {
                'packet_number': num,
                'timestamp': packet.sniff_time,
                'source_ip': packet.ip.src if hasattr(packet, 'ip') else '0.0.0.0',
                'dest_ip': packet.ip.dst if hasattr(packet, 'ip') else '255.255.255.255',
                'source_mac': getattr(bootp, 'chaddr', ''),
                'client_ip': getattr(bootp, 'ciaddr', '0.0.0.0'),
                'your_ip': getattr(bootp, 'yiaddr', '0.0.0.0'),
                'server_ip': getattr(bootp, 'siaddr', '0.0.0.0'),
                'message_type': msg_type,
                'transaction_id': getattr(bootp, 'id', '0'),
                'lease_time': None
            }
            
            self.dhcp_events.append(event)
            print(f"    [Пакет {num}] {msg_type} (BOOTP)")
            
        except Exception as e:
            print(f"[-] Ошибка обработки BOOTP пакета {num}: {e}")
    
    def process_generic_packet(self, packet, num):
        """Обработка пакета с DHCP информацией (общий случай)"""
        try:
            # Пробуем найти DHCP информацию в любом виде
            event = {
                'packet_number': num,
                'timestamp': packet.sniff_time,
                'source_ip': packet.ip.src if hasattr(packet, 'ip') else '0.0.0.0',
                'dest_ip': packet.ip.dst if hasattr(packet, 'ip') else '255.255.255.255',
                'source_mac': '',
                'client_ip': '0.0.0.0',
                'your_ip': '0.0.0.0',
                'server_ip': '0.0.0.0',
                'message_type': 'DHCP',
                'transaction_id': '0',
                'lease_time': None
            }
            
            # Проверяем строковое представление пакета на наличие типа DHCP
            packet_str = str(packet)
            if 'Discover' in packet_str:
                event['message_type'] = 'DISCOVER'
            elif 'Offer' in packet_str:
                event['message_type'] = 'OFFER'
            elif 'Request' in packet_str:
                event['message_type'] = 'REQUEST'
            elif 'ACK' in packet_str:
                event['message_type'] = 'ACK'
            elif 'NAK' in packet_str:
                event['message_type'] = 'NAK'
            
            self.dhcp_events.append(event)
            print(f"    [Пакет {num}] {event['message_type']} (generic)")
            
        except Exception as e:
            print(f"[-] Ошибка обработки generic пакета {num}: {e}")
    
    def extract_leases(self):
        """Извлечение информации о DHCP арендах"""
        print("\n[+] Анализ DHCP аренд (DORA процесс)...")
        
        # Группировка по transaction ID
        transactions = defaultdict(list)
        
        for event in self.dhcp_events:
            tid = event['transaction_id']
            transactions[tid].append(event)
        
        # Анализируем каждый transaction
        for tid, events in transactions.items():
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
            
            # Если есть полный DORA процесс
            if discover and offer and request and ack:
                try:
                    total_time = (ack['timestamp'] - discover['timestamp']).total_seconds()
                except:
                    total_time = 0
                
                lease_info = {
                    'transaction_id': tid,
                    'mac_address': offer.get('source_mac', ''),
                    'assigned_ip': ack.get('your_ip', ''),
                    'server_ip': ack.get('server_ip', ''),
                    'discover_time': discover['timestamp'],
                    'offer_time': offer['timestamp'],
                    'request_time': request['timestamp'],
                    'ack_time': ack['timestamp'],
                    'total_time_seconds': total_time
                }
                self.dhcp_leases.append(lease_info)
                print(f"    [Transaction {tid}] Выдан IP: {ack.get('your_ip', 'N/A')}")
        
        print(f"[+] Найдено полных DORA процессов: {len(self.dhcp_leases)}")
    
    def save_artifacts(self, artifacts_dir='artifacts'):
        """Сохранение артефактов"""
        print(f"\n[+] Сохранение артефактов...")
        
        os.makedirs(artifacts_dir, exist_ok=True)
        
        if self.dhcp_events:
            # Сохраняем события
            df_events = pd.DataFrame(self.dhcp_events)
            events_file = os.path.join(artifacts_dir, 'dhcp_events.csv')
            df_events.to_csv(events_file, index=False, encoding='utf-8')
            print(f"[+] Сохранено событий: {events_file} ({len(df_events)} записей)")
        
        if self.dhcp_leases:
            # Сохраняем аренды
            df_leases = pd.DataFrame(self.dhcp_leases)
            leases_file = os.path.join(artifacts_dir, 'dhcp_leases.csv')
            df_leases.to_csv(leases_file, index=False, encoding='utf-8')
            print(f"[+] Сохранено аренд: {leases_file} ({len(df_leases)} записей)")
    
    def create_visualizations(self, outputs_dir='outputs'):
        """Создание визуализаций"""
        print(f"\n[+] Создание визуализаций...")
        
        os.makedirs(outputs_dir, exist_ok=True)
        
        if not self.dhcp_events:
            print("[-] Нет данных для визуализации")
            return
        
        df = pd.DataFrame(self.dhcp_events)
        sns.set_style("whitegrid")
        
        # 1. График сообщений по времени
        plt.figure(figsize=(12, 6))
        try:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['time_sec'] = (df['timestamp'] - df['timestamp'].min()).dt.total_seconds()
            
            for msg_type in df['message_type'].unique():
                subset = df[df['message_type'] == msg_type]
                plt.scatter(subset['time_sec'], [1]*len(subset), label=msg_type, s=100)
            
            plt.xlabel('Время (секунды от начала)')
            plt.ylabel('События')
            plt.title('DHCP сообщения во времени')
            plt.legend()
            plt.yticks([])
            plt.grid(True, axis='x')
            
            output_file = os.path.join(outputs_dir, 'dhcp_messages_over_time.png')
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            print(f"[+] Сохранен график: {output_file}")
        except Exception as e:
            print(f"[-] Ошибка создания графика 1: {e}")
            plt.close()
        
        # 2. Диаграмма типов сообщений
        plt.figure(figsize=(8, 8))
        msg_counts = df['message_type'].value_counts()
        
        if len(msg_counts) > 0:
            colors = plt.cm.Set3(range(len(msg_counts)))
            plt.pie(msg_counts.values, labels=msg_counts.index, autopct='%1.1f%%', 
                   colors=colors, startangle=90)
            plt.title('Распределение типов DHCP сообщений')
            
            output_file = os.path.join(outputs_dir, 'dhcp_message_types.png')
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            print(f"[+] Сохранен график: {output_file}")
        else:
            plt.close()
    
    def generate_report(self):
        """Генерация отчета"""
        print("\n" + "="*70)
        print("ОТЧЕТ ПО АНАЛИЗУ DHCP ТРАФИКА")
        print("="*70)
        
        print(f"\n1. ОБЩАЯ СТАТИСТИКА:")
        print(f"   - Всего DHCP событий: {len(self.dhcp_events)}")
        print(f"   - Полных DORA процессов: {len(self.dhcp_leases)}")
        
        if self.dhcp_events:
            df = pd.DataFrame(self.dhcp_events)
            
            print(f"\n2. ТИПЫ СООБЩЕНИЙ:")
            for msg_type, count in df['message_type'].value_counts().items():
                print(f"   - {msg_type}: {count}")
            
            print(f"\n3. УЧАСТНИКИ:")
            print(f"   - DHCP серверы: {df['server_ip'].unique()}")
            print(f"   - Клиентов (по IP): {df['source_ip'].nunique()}")
            
            print(f"\n4. ВЫДАННЫЕ IP АДРЕСА:")
            for lease in self.dhcp_leases:
                print(f"   - {lease.get('assigned_ip', 'N/A')} (MAC: {lease.get('mac_address', 'N/A')})")
        
        print("\n" + "="*70)
        print("ВЫВОДЫ:")
        print("="*70)
        
        # Проверка на аномалии
        if len(self.dhcp_leases) > 0:
            print("✓ Обнаружен успешный DHCP handshake")
            print("✓ Клиент получил IP адрес от сервера")
        else:
            print("! Не найдено полных DORA процессов")
        
        print("\n[+] Анализ завершен!")


def main():
    """Основная функция"""
    pcap_file = 'data/dhcp.pcapng'
    
    if not os.path.exists(pcap_file):
        print(f"[-] Ошибка: файл {pcap_file} не найден!")
        print("    Убедитесь, что файл находится в папке data/")
        return
    
    analyzer = DHCPAnalyzer(pcap_file)
    
    if analyzer.load_and_analyze():
        analyzer.extract_leases()
        analyzer.save_artifacts()
        analyzer.create_visualizations()
        analyzer.generate_report()
    else:
        print("[-] Не удалось проанализировать файл")


if __name__ == "__main__":
    main()
