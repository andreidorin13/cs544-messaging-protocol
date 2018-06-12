#!/usr/bin/python
'''
Andrei Dorin
06/10/2018
WISP protocol session for a WISP client
'''

import logging
import time
import threading
import queue
import select
import sys

from wisp_common import State, WispRequest, WispResponse
import wisp_common as wcom

class WispServer(threading.Thread):
    '''
    Server thread to be spawned per connected client
    '''
    def __init__(self, conn, req_callbacks, msg_callback):
        super().__init__(daemon=True)
        self.user = None
        self.target = None
        self.msgq = queue.Queue()

        self._logger = logging.getLogger(__name__)
        self._conn = conn
        self._req_callbacks = req_callbacks
        self._msg_callback = msg_callback
        self._auth_counter = 0

        self._working = threading.Event()
        self._working.set()
        self._state = State.Listening
        self._handlers = {
            WispRequest.AUTH: self._handle_auth,
            WispRequest.LIST: lambda _, __: self._req_callbacks[WispRequest.LIST](self.user),
            WispRequest.SEARCH: lambda term, _: self._req_callbacks[WispRequest.SEARCH](self.user, term),
            WispRequest.ADD: lambda target, _: self._req_callbacks[WispRequest.ADD](self.user, target),
            WispRequest.DEL: lambda target, _: self._req_callbacks[WispRequest.DEL](self.user, target),
            WispRequest.QUIT: self._handle_quit,
            WispRequest.CONV: self._handle_conv
        }

        self._version_handshake()

    def run(self):
        '''
        Overriting the run function for a thread
        Main event loop of thread
        STATEFUL
        '''
        while self._working.isSet():
            try:
                # If conversation we are dealing with messages
                if self._state == State.Conversation:
                    # check socket for incoming messages
                    read, _, _ = select.select([self._conn], [], [], 0)
                    if read:
                        self._logger.info(f'Message received from {self.user}')
                        msg = wcom.parse_message(self._conn, self._logger)
                        if msg is None:
                            sys.exit(1)
                        self._logger.debug(f'Parsed message: {msg}')
                        if msg.text == '':
                            self._state = State.Command
                        else:
                            self._msg_callback(self.target, msg)
                    # check user msg queue for outgoing messages
                    try:
                        msg = self.msgq.get(block=False)
                        self._conn.send(wcom.build_msg(msg.time, msg.text))
                    except queue.Empty:
                        pass
                    time.sleep(0.01)
                # Else only command PDUs allowed
                else:
                    req = self._parse_request()
                    self._logger.info(f'Received command: {req}')
                    # Checking if command is allowed in current state
                    if req.cmd in wcom.STATE_MAP[self._state]:
                        outcome, data = self._handlers[req.cmd](req.arg1, req.arg2)
                        if outcome:
                            self._send_res(WispResponse.OK, data)
                        else:
                            self._send_res(WispResponse.ERROR, data)
            except Exception as err:
                self._logger.error(f'Event loop exception: {err}')
                self._logger.debug('Closing connection, exiting thread')
                self._conn.close()
                sys.exit(1)

    def join(self, timeout=None):
        '''Added join method, for testing if thread is alive'''
        self._working.clear()
        threading.Thread.join(self, timeout)

    def check_msg_state(self):
        '''Checks if thread is ready to receive messages'''
        return True if self._state == State.Conversation else False

    def _version_handshake(self):
        '''Sync function for negociating version, called after client connects'''
        versions = ['1.1']
        self._logger.debug(f'Sending version list: {versions}')
        self._send_res(WispResponse.OK, versions)

        req = self._parse_request()
        if req.cmd != WispRequest.VERSION:
            self._logger.error('Invalid version response')
            self._send_res(WispResponse.ERROR, ['Invalid version response'])
            sys.exit(1)

        if req.arg1 not in versions:
            self._logger.info('Unsupported version')
            self._send_res(WispResponse.ERROR, ['Unsupported version'])
            sys.exit(1)

        self._send_res(WispResponse.OK)
        self._state = State.Authentication

    # ----- Special command handlers -----
    def _handle_auth(self, username, password):
        '''Auth handle, if succesfful, save user, change state'''
        outcome, data = self._req_callbacks[WispRequest.AUTH](username, password)
        if outcome:
            self._state = State.Command
            self.user = username
        else:
            self._auth_counter += 1
            if self._auth_counter > 5:
                self._logger.info('User timed out')
                sys.exit(1)
        return outcome, data

    def _handle_conv(self, target, _):
        '''Conversation handle, if succesfful, save target, change state'''
        outcome, data = self._req_callbacks[WispRequest.CONV](self.user, target)
        if outcome:
            self._state = State.Conversation
            self.target = target
        return outcome, data

    def _handle_quit(self, _, __):
        '''Handle Quit command, close nicely'''
        self._logger.info(f'Closing connection with {self._conn.getpeername()}')
        sys.exit(0)

    # ----- Utility functions -----
    def _parse_request(self):
        '''Parser for request PDUs'''
        packet = self._recv(36)
        cmd = packet[:4].decode()
        if WispRequest.valid(cmd):
            return WispRequest(cmd, wcom.parse_pkt_field(packet[4:20].decode()), wcom.parse_pkt_field(packet[20:].decode()))
        else:
            self._logger.error('Bad request received from {self._conn.getpeername()}')
            self._handle_quit(None, None)

    def _recv(self, size):
        '''Utility receive wrapper for error checking'''
        msg = self._conn.recv(size)
        if len(msg) != size:
            self._logger.error(f'Read less than expected: {len(msg)}/{len(size)}')
            self._handle_quit(None, None)
        return msg

    def _send_res(self, status, data=[]):
        '''Utility func for logging and sending responses'''
        self._logger.debug(f'Sending message: {status}: {data}')
        self._conn.send(wcom.build_res(status, len(data), *data))
