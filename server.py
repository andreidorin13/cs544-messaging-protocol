#!/usr/bin/python
'''
Andrei Dorin
06/10/2018
Server interface for WISP server implementation
'''

import argparse
import logging
import sys
import signal
import socket as so
import threading

import wisp_common as wcom
from wisp_common import WispRequest
from wisp_server import WispServer

# Database for user accounts, resets on server shutdown
DATASTORE = {
    'andrei': {
        'password': 'dorin',
        'friends': ['safa', 'cameron', 'kenny', 'colbert']
    },
    'cameron': {
        'password': 'graybill',
        'friends': ['andrei']
    },
    'safa': {
        'password': 'aman',
        'friends': ['andrei']
    },
    'michael': {
        'password': 'kain',
        'friends': []
    },
    'kenny': {
        'password': 'li',
        'friends': ['andrei']
    },
    'colbert': {
        'password': 'zhu',
        'friends': ['andrei']
    }
}

class Server():
    '''
    Main Server class
    Handles UDP service discovery
    Accepts TCP connections and delegates to WISP sessions
    Provides callbacks for all commands
    '''
    def __init__(self):
        self._logger = logging.getLogger(__name__)
        self._socket = None
        self._data_lock = threading.Lock()
        self._sessions = []
        self._sess_lock = threading.Lock()
        self._handlers = {
            WispRequest.AUTH: self._handle_auth,
            WispRequest.LIST: self._handle_list,
            WispRequest.SEARCH: self._handle_search,
            WispRequest.ADD: self._handle_add,
            WispRequest.DEL: self._handle_del,
            WispRequest.CONV: self._handle_conv,
        }

    def start(self, addr, port):
        '''Start UDP service discovery and TCP socket accepts'''
        self._logger.info(f'Starting service descovery on broadcast:{wcom.WISP_DEFAULT_PORT}')
        threading.Thread(target=self.service_descovery, args=(wcom.WISP_DEFAULT_PORT,), daemon=True).start()
        self._setup_tcp_sock(addr, port)

        # CONCURRENT
        while True:
            conn, addr = self._socket.accept()
            self._logger.info(f'New connection from {addr}')
            # Create new wisp session on a different thread for every client
            # Since WispServer inherits from Thread, start() calls the run()
            # Function defined in wisp_server.py
            server = WispServer(conn, self._handlers, self._handle_message)
            server.start()
            # Save session for later
            with self._sess_lock:
                self._sessions.append(server)

    @classmethod
    def service_descovery(cls, port):
        '''Service descovery system, meant to run as a separate thread'''
        # Getting local IP
        temp = so.socket(so.AF_INET, so.SOCK_DGRAM)
        temp.connect(('8.8.8.8', port))
        addr = temp.getsockname()[0]
        temp.close()

        while True:
            udp = so.socket(so.AF_INET, so.SOCK_DGRAM)
            udp.setsockopt(so.SOL_SOCKET, so.SO_REUSEADDR, 1)
            udp.setsockopt(so.SOL_SOCKET, so.SO_BROADCAST, 1)
            udp.bind(('', port))
            data = udp.recv(len(wcom.WISP_ARP_REQ))

            if data == wcom.WISP_ARP_REQ:
                udp.sendto(wcom.WISP_ARP_RES + addr.encode(), ('255.255.255.255', port))

    def _setup_tcp_sock(self, addr, port):
        '''TCP socket init'''
        self._logger.info(f'Starting TCP socket on {addr}:{port}')
        self._socket = so.socket(so.AF_INET, so.SOCK_STREAM)
        self._socket.setsockopt(so.SOL_SOCKET, so.SO_REUSEADDR, 1)
        self._socket.bind((addr, port))
        self._socket.listen(wcom.WISP_DEFAULT_CONNECTION_COUNT)

    # ----- Handlers for all commands -----
    def _handle_auth(self, username, password):
        '''Verifies username and password againsts database'''
        with self._data_lock:
            if username in DATASTORE:
                if DATASTORE[username]['password'] == password:
                    return True, []
            return False, ['Invalid Cred']

    def _handle_list(self, username):
        '''Returns friends list'''
        with self._data_lock:
            if username not in DATASTORE:
                return False, ['Invalid user']
            return True, DATASTORE[username]['friends']

    def _handle_search(self, owner, lookup):
        '''Searches database for users matching "lookup"'''
        user_list = []
        with self._data_lock:
            for user in DATASTORE:
                if user != owner and lookup in user and user not in DATASTORE[owner]['friends']:
                    user_list.append(user)
        return True, user_list

    def _handle_add(self, owner, user):
        '''Adds new friend to friend list to both users'''
        with self._data_lock:
            if owner not in DATASTORE or user not in DATASTORE:
                return False, ['Invalid User']
            DATASTORE[owner]['friends'].append(user)
            DATASTORE[user]['friends'].append(owner)
            return True, []

    def _handle_del(self, owner, user):
        '''Deletes friend from both users lists'''
        with self._data_lock:
            if owner not in DATASTORE or user not in DATASTORE[owner]['friends']:
                return False, ['Invalid Users']
            DATASTORE[owner]['friends'].remove(user)
            DATASTORE[user]['friends'].remove(owner)
            return True, []

    def _handle_conv(self, owner, target):
        '''Validates user is online for conversation'''
        with self._data_lock:
            if target not in DATASTORE[owner]['friends']:
                return False, ['Friend Unknown']
            with self._sess_lock:
                for conn in self._sessions:
                    if conn.user == target:
                        return True, []
                return False, ['User offline']

    def _handle_message(self, receiver, msg):
        '''
        Route message to destination session
        Also cleans up dead sessions
        '''
        with self._sess_lock:
            for i in range(len(self._sessions) -1, -1, -1):
                connection = self._sessions[i]
                if not connection.is_alive():
                    del self._sessions[i]
                    continue
                if connection.user == receiver and connection.check_msg_state():
                    self._logger.debug(f'Routing message to {receiver}: {msg}')
                    connection.msgq.put(msg)


def signal_sigint(_, __):
    '''
    Signal handler for KeyboardInterrupt or SIGINT
    '''
    print('SIGINT Received, shutting down')
    sys.exit(0)

def main():
    '''
    Main entry point of server
    Argument parsing and initializing client
    '''
    parser = argparse.ArgumentParser(description='WISP chat server')
    parser.add_argument('-v', '--verbosity', type=int, default=4, choices=[4, 3, 2, 1],
                        help='Verbosity of logger, 4: Error, 3: Warning, 2: Info, 1: Debug')
    args = parser.parse_args()

    logging.basicConfig()
    logging.getLogger().setLevel(args.verbosity * 10)

    signal.signal(signal.SIGINT, signal_sigint)

    # SERVICE
    server = Server()
    server.start(wcom.WISP_DEFAULT_HOST, wcom.WISP_DEFAULT_PORT)

if __name__ == '__main__':
    main()
