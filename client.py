#!/usr/bin/python
'''
Andrei Dorin
06/10/2018
User interface for WISP chat implementation
'''

import argparse
import logging
import signal
import sys
import time
import queue
import select
import getpass

from wisp_client import WispClient
from wisp_common import State, WispRequest, WispResponse, WispMessage, WISP_DEFAULT_PORT

class Client():
    '''
    Chat client class
    Handles drawing menu and buttons
    Uses inner WispClient for networking
    '''
    def __init__(self):
        self._logger = logging.getLogger()
        self._wclient = WispClient()
        self._friend_list = None

    # ---- Public Functions ----
    def connect(self, host, port):
        '''Connect to chat server'''
        if not self._wclient.connect(host, port):
            self._logger.error('Client exiting')
            sys.exit(1)

    def discover(self):
        '''Attempt to discover IP of chat server on network'''
        if not self._wclient.discover(WISP_DEFAULT_PORT):
            self._logger.error('Client exiting')
            sys.exit(1)

    def start(self):
        '''
        Start WispClient event loop
        Begin authentication procedure
        '''
        self._wclient.start()

        response = self._auth()
        while response.code != WispResponse.OK:
            print(f'\033[31m{response.data}\033[39m')
            response = self._auth()
        self._wclient.state = State.Command
        self._draw_main_menu()


    def _draw_main_menu(self):
        '''
        UI
        Main application menu
        Delegates to sub-menus
        '''
        user_cmd = None
        cmd_list = [
            self._search,
            self._delete,
            self._talk,
            self._quit
        ]

        while user_cmd != len(cmd_list):
            self._friends()
            print(f'Commands:\n1. Search for Friends\n2. Delete Friend\n3. Talk to Friend\n4. Exit')
            user_cmd = self._get_user_input(1, len(cmd_list))
            cmd_list[user_cmd-1]()

    # ---- Client Commands + Menus ----
    def _auth(self):
        '''Gather username and password, attempt blocking authentication call'''
        username = input('Username: ')
        while len(username) > 16:
            username = input('Username too long, try again: ')
        password = getpass.getpass()
        while len(password) > 16:
            password = input('Password too long, try again: ')
        return self._blocking_request(WispRequest.AUTH, username, password)

    def _search(self):
        '''
        Query server for users containting search phrase
        Offer option of adding them as friends
        '''
        phrase = input('Search phrase: ')
        while len(phrase) > 16:
            phrase = input('Phrase too long, try again: ')

        # Display search results
        results = self._blocking_request(WispRequest.SEARCH, phrase).data
        index = self._draw_menu('Results', results)
        if index == -1:
            return

        # If here then make friend request
        response = self._blocking_request(WispRequest.ADD, results[index])
        if response.code == WispResponse.OK:
            print(f'Friend added succesfully!')
        else:
            print(f'\033[31m{response.data}\033[39m')

    def _friends(self):
        '''Retrieve and draw friend list'''
        self._friend_list = self._blocking_request(WispRequest.LIST).data
        print('Friends:')
        for i, friend in enumerate(self._friend_list):
            print(f'{i+1}. {friend}')

    def _delete(self):
        '''Delete a friend'''
        index = self._draw_menu('Deleting Friend:', self._friend_list)
        if index == -1:
            return
        self._blocking_request(WispRequest.DEL, self._friend_list[index])

    def _talk(self):
        '''Start a conversation with a friend'''
        index = self._draw_menu('Select Friend to talk to: ', self._friend_list)
        if index == -1:
            return
        response = self._blocking_request(WispRequest.CONV, self._friend_list[index])
        if response.code == WispResponse.OK:
            self._wclient.state = State.Conversation
            self._async_conv()
            self._wclient.state = State.Command
        else:
            print(f'\033[31m{response.data}\033[39m')

    def _quit(self):
        '''Nicely close connection to server'''
        print('Sending goodbye message')
        self._wclient.reqq.put(WispRequest(WispRequest.QUIT))
        time.sleep(.250) # make sure request get processed before exiting
        sys.exit(0)

    # ----- Helper Functions -----
    def _blocking_request(self, cmd, arg1=None, arg2=None):
        '''Sends command to server and awaits response'''
        res = None
        self._wclient.reqq.put(WispRequest(cmd, arg1, arg2))
        while res is None:
            try:
                res = self._wclient.resq.get(block=False)
            except queue.Empty:
                pass
            time.sleep(0.01)
        return res

    def _async_conv(self):
        print('New conversion! Empty line to return to menu')
        line = None

        while line != '':
            read, _, _ = select.select([sys.stdin], [], [], 0)
            if read:
                line = sys.stdin.readline().rstrip()
                if len(line) > 127:
                    for batch in [line[i:i+127] for i in range(0, len(line), 127)]:
                        self._wclient.reqq.put(WispMessage(batch))
                else:
                    self._wclient.reqq.put(WispMessage(line))
            try:
                res = self._wclient.resq.get(block=False)
                print(f'\033[92m{res}\033[39m')
            except queue.Empty:
                pass
            time.sleep(0.01)
        print('Returning to menu!')

    @classmethod
    def _draw_menu(cls, header, options):
        '''Draws menu based on list of options'''
        upper = len(options)+1
        print(header)
        for i, opt in enumerate(options):
            print(f'{i+1}. {opt}')
        print(f'Press {upper} to go back')
        index = cls._get_user_input(1, upper)
        return -1 if index == upper else index-1

    @classmethod
    def _get_user_input(cls, lower, upper):
        '''Gets user input as int within lower/upper bounds'''
        user_cmd = -1
        while not lower <= user_cmd <= upper:
            try:
                user_cmd = int(input('Choose Number: '))
            except (ValueError, EOFError):
                continue
        return user_cmd


def signal_sigint(_, __):
    '''
    Signal handler for KeyboardInterrupt or SIGINT
    '''
    print('SIGINT Received, shutting down')
    sys.exit(0)

def main():
    '''
    Main entry point of client
    Argument parsing and initializing client
    '''
    parser = argparse.ArgumentParser(description='WISP protocol chat client')
    parser.add_argument('-H', '--host', type=str,
                        help='IP of server, if none is specified, service discovery will be attempted')
    parser.add_argument('-p', '--port', type=int, default=32500,
                        help='Port of server to connect, if none is specified, protocol default 32500 will be used')
    parser.add_argument('-v', '--verbosity', type=int, default=4, choices=[4, 3, 2, 1],
                        help='Verbosity of logger, 4: Error, 3: Warning, 2: Info, 1: Debug')
    args = parser.parse_args()

    logging.basicConfig()
    logging.getLogger().setLevel(args.verbosity * 10)

    signal.signal(signal.SIGINT, signal_sigint)

    # CLIENT
    client = Client()
    if args.host:
        client.connect(args.host, args.port)
    else:
        client.discover()

    client.start()

if __name__ == '__main__':
    main()
