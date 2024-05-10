from scapy.all import *
from scapy.layers.inet6 import _ICMPv6  # Importar ICMPv6
import pandas as pd
"""Pene"""""
print("Ejecutando")

# Lista para almacenar los paquetes capturados
captured_packets = []

# Función para procesar paquetes capturados
def process_packet(packet):
    packet_info = {}
    if IP in packet:
        if TCP in packet:
            packet_info = {
                "protocolo": "TCP",
                "ip_origen": packet[IP].src,
                "puerto_origen": packet[TCP].sport,
                "ip_destino": packet[IP].dst,
                "puerto_destino": packet[TCP].dport,
            }
        elif UDP in packet:
            packet_info = {
                "protocolo": "UDP",
                "ip_origen": packet[IP].src,
                "puerto_origen": packet[UDP].sport,
                "ip_destino": packet[IP].dst,
                "puerto_destino": packet[UDP].dport,
            }
        elif ICMP in packet:
            packet_info = {
                "protocolo": "ICMP",
                "ip_origen": packet[IP].src,
                "ip_destino": packet[IP].dst,
                "tipo": packet[ICMP].type,
                "codigo": packet[ICMP].code,
            }
    elif IPv6 in packet:
        if _ICMPv6 in packet:
            packet_info = {
                "protocolo": "ICMPv6",
                "ip_origen": packet[IPv6].src,
                "ip_destino": packet[IPv6].dst,
                "tipo": packet[ICMPv6].type,
                "codigo": packet[ICMPv6].code,
            }
    
    if packet_info:
        captured_packets.append(packet_info)


# Captura de paquetes TCP en la interfaz de red especificada
sniff(prn=process_packet, iface="wlp3s0", filter="tcp",count=100)

# Convertir la lista de diccionarios en un DataFrame de Pandas
df = pd.DataFrame(captured_packets)

# Mostrar el DataFrame
print(df)
