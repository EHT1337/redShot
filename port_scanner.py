#!/usr/bin/env python3
import os
import sys
import nmap
import argparse
import subprocess
import shlex
import re

def masscan_scan(target, ports, rate, protocol, interface=None):
    """Realiza uma varredura de portas usando o masscan e retorna uma lista de portas abertas.

    Args:
        target (str): O IP ou intervalo de IPs a serem verificados (notação CIDR).
        ports (str): O intervalo de portas a serem verificadas (por exemplo, '1-1024').
        rate (str): A taxa de pacotes por segundo enviados pelo masscan.
        protocol (str): O protocolo a ser verificado ('tcp' ou 'udp').
        interface (str, optional): A interface de rede a ser usada pelo masscan.

    Returns:
        list[int]: Uma lista de portas abertas encontradas no alvo.
    """
    masscan_command = f"masscan {target} -p{ports} --rate={rate} -p{protocol}"
    if interface:
        masscan_command += f" -e {interface}"
    masscan_command = shlex.split(masscan_command)
    
    try:
        output = subprocess.check_output(masscan_command).decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error executing masscan: {e}")
        return []
    
    open_ports = []
    for match in re.finditer(rf"Discovered open port (\d+)/{protocol}", output):
        open_ports.append(match.group(1))
    return open_ports

def nmap_scan(target, tcp_ports, udp_ports):
    """Realiza uma varredura de serviços e versões usando o nmap nas portas abertas fornecidas.

    Args:
        target (str): O IP ou intervalo de IPs a serem verificados (notação CIDR).
        tcp_ports (list[int]): Uma lista de portas TCP abertas encontradas pelo masscan.
        udp_ports (list[int]): Uma lista de portas UDP abertas encontradas pelo masscan.

    Returns:
        dict: Um dicionário contendo informações detalhadas sobre os serviços e versões encontrados.
    """
    nm = nmap.PortScanner()
    ports_to_scan = []
    
    if tcp_ports:
        ports_to_scan.append((','.join([port.split('/')[0] for port in tcp_ports]), '-sV -A --script=default'))
    if udp_ports:
        ports_to_scan.append((','.join([port.split('/')[0] for port in udp_ports]), '-sU -sV --script=default'))

    for ports, args in ports_to_scan:
        nm.scan(hosts=target, ports=ports, arguments=args)

    return nm[target] if target in nm.all_hosts() else {'tcp': {}, 'udp': {}}

def colored_text(text, color):
    """Retorna o texto com a cor especificada aplicada usando códigos de escape ANSI.

    Args:
        text (str): O texto que você deseja colorir.
        color (str): A cor que você deseja aplicar ao texto (por exemplo, 'green').

    Returns:
        str: O texto colorido com a cor especificada.
    """    
    color_codes = {
        'green': '\033[92m',
        'red': '\033[31m',
        'yellow': '\033[33m',
        'blue': '\033[34m',
        'magenta': '\033[35m',
        'cyan': '\033[36m',
        'white': '\033[37m',
        'reset': '\033[0m'
    }
    return f"\033[1m{color_codes.get(color, '\033[0m')}{text}\033[0m"

def main():
    """A função principal que coordena a execução do script.
    
    1. Processa os argumentos de linha de comando.
    2. Realiza uma varredura de portas TCP e UDP abertas usando o masscan.
    3. Realiza uma varredura de serviços e versões do nmap nas portas abertas.
    4. Exibe informações sobre os serviços e versões encontrados no terminal.
    """    
    parser = argparse.ArgumentParser(description="A Python tool to scan open TCP and UDP ports using masscan and perform Nmap service/version scanning")
    parser.add_argument("target", help="Target IP address or range (CIDR notation)")
    parser.add_argument("--ports", default="1-65535", help="Port range to scan (default: 1-65535 TCP/UDP)")
    parser.add_argument("--rate", type=int, default=1000, help="Scan rate for masscan (default: 1000)")
    parser.add_argument("--interface", default="tun0", help="Select the network adapter card (default: tun0)")
    parser.add_argument("--udp", action="store_true", help="Enable UDP port scanning (default: disabled)")
    args = parser.parse_args()

    if not os.geteuid() == 0:
        sys.exit("This script requires root privileges to run.")

    print(f"{colored_text('[*]', 'green')}\033[1mScanning open TCP ports on {args.target}...\033[0m")
    open_tcp_ports = masscan_scan(args.target, args.ports, args.rate, "tcp", args.interface)
    if open_tcp_ports:
        print(f"Found open TCP ports: {', '.join(map(str, open_tcp_ports))}")
    else:
        print(f"{colored_text('[!]', 'red')}\033[1mNo TCP open ports found.\033[0m")

    if args.udp:
        print(f"{colored_text('[*]', 'green')}\033[1mScanning open UDP ports on {args.target}...\033[0m")
        open_udp_ports = masscan_scan(args.target, args.ports, args.rate, "udp", args.interface)
        if open_udp_ports:
            print(f"Found open UDP ports: {', '.join(map(str, open_udp_ports))}")
    else:
        print(f"{colored_text('[!]', 'red')}\033[1mNo UDP ports found or scanned.\033[0m")
        open_udp_ports = []

    print(f"{colored_text('[!]', 'green')}\033[1mRunning Nmap service and version scanning on {args.target}...\033[0m")
    nmap_result = nmap_scan(args.target, open_tcp_ports, open_udp_ports)

    if open_tcp_ports:
        for port in nmap_result['tcp']:
            print(f"TCP Port {port}: \033[1m{nmap_result['tcp'][port]['name']} ({nmap_result['tcp'][port]['product']}, {nmap_result['tcp'][port]['version']})\033[0m")
    else:
        print(f"{colored_text('[!]', 'red')}\033[1mNo TCP open ports found.\033[0m")
    if open_udp_ports:
        for port in nmap_result['udp']:
            print(f"UDP Port {port}: \033[1m{nmap_result['udp'][port]['name']} ({nmap_result['udp'][port]['product']}, {nmap_result['udp'][port]['version']})\033[0m")

if __name__ == "__main__":
    main()
