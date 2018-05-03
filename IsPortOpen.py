import socket
from platform import system as system_name  # Returns the system/OS name
import subprocess  # Execute a shell command
import paramiko


TIMEOUT = 2

def TestPortOpen(ip, port):
    """
    Returns True if connection is successful.
    Otherwise Function returns False
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(1)
        s.connect((ip, int(port)))
        s.shutdown(TIMEOUT)
        return True
    except:
        return False


def TestPing(ipAddress):
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """
    # Ping command count option as function of OS
    param = '-n' if system_name().lower() == 'windows' else '-c'

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '1', ipAddress]
    # Pinging
    pingCommand = subprocess.Popen(command, stdout=subprocess.PIPE)
    outputPing = pingCommand.communicate()[0].decode()
    returnCode = pingCommand.returncode
    if 'TTL' in outputPing and returnCode == 0:
        return True
    else:
        return False


def TestShellLogin(ipAddress, username, password):
    """
    Returns True if shell login is successful.
    Otherwise Function returns error String
    """

    sshTransaction = paramiko.SSHClient()
    sshTransaction.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        sshTransaction.connect(ipAddress, username=username, password=password, timeout=TIMEOUT)
        return True
    except paramiko.AuthenticationException:
        return 'Authentication Error'
    except (paramiko.BadHostKeyException, paramiko.SSHException, socket.error):
        return 'Connection Error'


# def TestPing2(ipAddress):
#     toping = subprocess.Popen(['ping', '-n', '1', ipAddress], stdout=subprocess.PIPE)
#     output = toping.communicate()[0]
#     returncode = toping.returncode
#     if 'TTL' in output.decode():
#         print(output.decode())
#     print(returncode)


