'''
Container module for
global variables, structs and methods
to be shared between client and server
'''
import time
import datetime
import struct
import os
from enum import Enum

# ----- Globals -----
WISP_DEFAULT_HOST = '0.0.0.0'
WISP_DEFAULT_PORT = 32500
WISP_DEFAULT_CONNECTION_COUNT = 100
WISP_ARP_REQ = b'Is anyone there?' # ~ Portal Turret
WISP_ARP_RES = b'WISPRES:'

# ---- Classes and Enums -----
class State(Enum):
    '''DFA state enum'''
    Listening = 1
    Authentication = 2
    Command = 3
    Conversation = 4

class WispRequest():
    '''
    Container for a request PDU
    Exposes all request command codes
    '''
    VERSION = 'VERS'
    AUTH = 'USPS'
    ADD = 'ADDU'
    DEL = 'DELU'
    LIST = 'LIST'
    SEARCH = 'SRCH'
    CONV = 'CONV'
    QUIT = 'QUIT'

    def __str__(self):
        return f'{self.cmd}({self.arg1}, {self.arg2})'

    def __init__(self, cmd, arg1=None, arg2=None):
        self.cmd = cmd
        self.arg1 = arg1
        self.arg2 = arg2

    @classmethod
    def valid(cls, value):
        '''Checks if value is valid command codes'''
        return value in [
            cls.VERSION,
            cls.AUTH,
            cls.ADD,
            cls.DEL,
            cls.LIST,
            cls.SEARCH,
            cls.CONV,
            cls.QUIT
        ]

class WispResponse():
    '''
    Container for a response PDU
    Exposes all response codes
    '''
    OK = 'OK'
    ERROR = 'ER'

    def __str__(self):
        return f'{self.code}: {self.data}'

    def __init__(self, code, data):
        self.code = code
        self.count = len(data)
        self.data = data

class WispMessage():
    '''Container for a message PDU'''
    def __str__(self):
        return f'@{datetime.datetime.fromtimestamp(self.time)}: {self.text}'

    def __init__(self, text, timestamp=None):
        self.time = timestamp or int(time.time())
        self.text = text

# Map for which Commands are valid in which state
STATE_MAP = {
    State.Listening: [WispRequest.VERSION],
    State.Authentication: [WispRequest.AUTH],
    State.Command: [
        WispRequest.ADD,
        WispRequest.DEL,
        WispRequest.LIST,
        WispRequest.SEARCH,
        WispRequest.CONV,
        WispRequest.QUIT
    ]
}

# ----- Common Packet Building/Parsing Functions -----
def build_req(cmd, arg1='', arg2=''):
    '''Builds request PDU'''
    one = f'{arg1}\0'.ljust(16)
    two = f'{arg2}\0'.ljust(16)
    return f'{cmd}{one}{two}'.encode()

def build_res(code, count, *args):
    '''Build response PDU'''
    header = code.encode() + struct.pack('<I', count)
    for arg in args:
        header += f'{arg}\0'.ljust(16).encode()
    return header

def build_msg(timestamp, buf):
    '''Build message PDU'''
    msg = struct.pack('<I', timestamp) + f'{buf}\0'.ljust(128).encode()
    return msg

def parse_message(socket, logger):
    '''Parser for messages PDU'''
    try:
        msg = socket.recv(132)
        if len(msg) < 132:
            logger.error('Message shorter than expected')
            raise Exception('Message too short')
        timestamp = struct.unpack('<I', msg[:4])[0]
        text = parse_pkt_field(msg[4:].decode())
        return WispMessage(text, timestamp)
    except Exception as err:
        logger.error('Malformed message received')
        logger.debug(err)
        return None

def parse_pkt_field(field):
    '''Parses PDU fields for null terminator'''
    for i, char in enumerate(field):
        if char == '\0':
            return field[:i]
    return field
