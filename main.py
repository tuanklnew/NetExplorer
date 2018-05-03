from prettytable import PrettyTable
from argparse import ArgumentParser
from queue import Queue
import ipaddress
import threading
from IsPortOpen import TestPortOpen, TestPing, TestShellLogin
import sys


TELNET_PORT = 23
SSH_PORT = 22
VNC_PORT = 5900
NUM_WORKER = 15
QUEUE = Queue()
RESULT = []


class HostStatus:
    ipAddress = '127.0.0.1'
    isPingSuccess = None
    isTelnetOpen = None
    isSSHOpen = None
    isVNCOpen = None
    isShellLoginSuccess = None

    def __init__(self, *args, **kwargs):
        self.ipAddress = kwargs['ipAddress']
        self.isPingSuccess = kwargs['isPingSuccess']
        self.isTelnetOpen = kwargs['isTelnetOpen']
        self.isSSHOpen = kwargs['isSSHOpen']
        self.isVNCOpen = kwargs['isVNCOpen']
        self.isShellLoginSuccess = kwargs['isShellLoginSuccess']

    def __str__(self):
        return 'ipAddress = {} \n' \
               'isPingSuccess = {} \n' \
               'isTelnetOpen = {} \n' \
               'isSSHOpen = {} \n' \
               'isVNCOpen = {} \n' \
               'isShellLoginSuccess = {}'.format(self.ipAddress,
                                                 self.isPingSuccess,
                                                 self.isTelnetOpen,
                                                 self.isSSHOpen,
                                                 self.isVNCOpen,
                                                 self.isShellLoginSuccess)


def GetResourceFromQueue(*args, **kwargs):
    while True:
        ipAddress = QUEUE.get()
        pingStatus = TestPing(ipAddress)
        telnetStatus = TestPortOpen(ipAddress, TELNET_PORT)
        sshStatus = TestPortOpen(ipAddress, SSH_PORT)
        vncStatus = TestPortOpen(ipAddress, VNC_PORT)

        if args[0]:
            shellLoginStatus = TestShellLogin(ipAddress, args[1], args[2])
        else:
            shellLoginStatus = None
        hostStatus = HostStatus(ipAddress=ipAddress,
                                isPingSuccess=pingStatus,
                                isTelnetOpen=telnetStatus,
                                isSSHOpen=sshStatus,
                                isVNCOpen=vncStatus,
                                isShellLoginSuccess=shellLoginStatus)
        RESULT.append(hostStatus)
        QUEUE.task_done()


def main():
    cliParser = ArgumentParser(description="Network Scanner Tool")
    inputGrp = cliParser.add_mutually_exclusive_group(required=True)
    inputGrp.add_argument('-f', '--file', help="Text file contains IP Address", type=str)
    inputGrp.add_argument('-i', '--ip', nargs='+', help="IP Addresses list", type=str)
    cliParser.add_argument('-s', '--shell', action='store_true', help='Test shell login')
    cliParser.add_argument('-u', '--username', required='--shell' in sys.argv, help='Username of shell')
    cliParser.add_argument('-p', '--password', required='--shell' in sys.argv, help='Password of shell')
    args = cliParser.parse_args()




    for worker in range(NUM_WORKER):
        thread = threading.Thread(target=GetResourceFromQueue, args=[args.shell, args.username, args.password])
        thread.daemon = True
        thread.start()
    if args.file:
        fileInput = open(args.file)
        ipAddresses = [x.strip() for x in fileInput]
        for ipAddress in ipAddresses:
            try:
                ipaddress.IPv4Address(ipAddress)
            except ipaddress.AddressValueError:
                print("[!] Can not parse {} as a IPv4 Address".format(ipAddress))
                continue
            else:
                QUEUE.put(ipAddress)
    else:
        for ipAddress in args.ip:
            try:
                ipaddress.IPv4Address(ipAddress)
            except ipaddress.AddressValueError:
                print("[!] Can not parse {} as a IPv4 Address".format(ipAddress))
                continue
            else:
                QUEUE.put(ipAddress)
    QUEUE.join()  # block until all tasks are done
    if args.shell:
        resultTable = PrettyTable(['IP Address', 'Ping', 'Telnet', 'SSH', 'VNC', 'Shell Login'])
        for host in RESULT:
            resultTable.add_row([host.ipAddress,
                                 'x' if host.isPingSuccess else ' ',
                                 'x' if host.isTelnetOpen else ' ',
                                 'x' if host.isSSHOpen else ' ',
                                 'x' if host.isVNCOpen else ' ',
                                 'x' if host.isShellLoginSuccess is True else host.isShellLoginSuccess])
    else:
        resultTable = PrettyTable(['IP Address', 'Ping', 'Telnet', 'SSH', 'VNC'])
        for host in RESULT:
            resultTable.add_row([host.ipAddress,
                                 'x' if host.isPingSuccess else ' ',
                                 'x' if host.isTelnetOpen else ' ',
                                 'x' if host.isSSHOpen else ' ',
                                 'x' if host.isVNCOpen else ' '])
    print(resultTable)


if __name__ == '__main__':
    print("  _   _      _     ______            _                     ")
    print(" | \ | |    | |   |  ____|          | |                    ")
    print(" |  \| | ___| |_  | |__  __  ___ __ | | ___  _ __ ___ _ __ ")
    print(" | . ` |/ _ \ __| |  __| \ \/ / '_ \| |/ _ \| '__/ _ \ '__|")
    print(" | |\  |  __/ |_  | |____ >  <| |_) | | (_) | | |  __/ |   ")
    print(" |_| \_|\___|\__| |______/_/\_\ .__/|_|\___/|_|  \___|_|   ")
    print("                              | |                          ")
    print("   Developed by J03y M4rK0v   |_|  ")
    print("")
    print("")
    main()
