#!/usr/bin/python
'''
Andrei Dorin
06/10/2018
Client implementation of WISP protocol
'''

import logging
import struct
import os
import queue
import threading
import socket as so
import select

from wisp_common import State, WispRequest, WispResponse, WispMessage
import wisp_common as wcom

class WispClient(threading.Thread):
    '''Network transport class for WISP protocol as thread'''
    def __init__(self):
        super().__init__(daemon=True)
        self.state = State.Listening
        self.reqq = queue.Queue()
        self.resq = queue.Queue()

        self._logger = logging.getLogger(__name__)
        self._working = threading.Event()
        self._working.set()
        self._conn = None
        self._handlers = {
            WispRequest.__name__: lambda req: self._conn.send(wcom.build_req(req.cmd, req.arg1, req.arg2)),
            WispMessage.__name__: lambda msg: self._conn.send(wcom.build_msg(msg.time, msg.text))
        }

    def connect(self, addr, port):
        '''Attempt connection to server over TCP'''
        try:
            self._conn = so.socket(so.AF_INET, so.SOCK_STREAM)
            self._conn.connect((addr, port))
            self._logger.info(f'New connection to {addr}:{port}')
            return self._version_handshake()
        except Exception as err:
            self._logger.error(f'Failed connection to {addr}:{port} due to {str(err)}')
            return False

    def discover(self, port):
        '''Attempt find server by requesting IP over boardcast'''
        self._logger.info('Attempting service discovery')
        addr = ''
        # Sending WISP ARP request
        udp = so.socket(so.AF_INET, so.SOCK_DGRAM)
        udp.setsockopt(so.SOL_SOCKET, so.SO_REUSEADDR, 1)
        udp.setsockopt(so.SOL_SOCKET, so.SO_BROADCAST, 1)
        udp.settimeout(30)
        udp.bind(('', port))
        udp.sendto(wcom.WISP_ARP_REQ, ('255.255.255.255', port))

        while addr == '':
            boardcast = udp.recv(len(wcom.WISP_ARP_RES) + 15) # 15 for 111.111.111.111
            if wcom.WISP_ARP_RES in boardcast:
                addr = boardcast[len(wcom.WISP_ARP_RES):].decode()
                self._logger.info(f'Found server at {addr}')
                return self.connect(addr, port)

    def run(self):
        '''
        Overriting the run function for a thread
        Main event loop of thread
        STATEFUL
        '''
        while self._working.isSet():
            # Parse outgoing
            try:
                req = self.reqq.get(True, 0.01)
                self._handlers[type(req).__name__](req)
                #self.resq.put(res)
            except queue.Empty:
                pass

            # Parse incoming
            read, _, _ = select.select([self._conn], [], [], 0.1)
            if read:
                if self.state in (State.Authentication, State.Command):
                    self.resq.put(self._parse_response())
                else:
                    msg = wcom.parse_message(self._conn, self._logger)
                    if msg is None:
                        os._exit(1)
                    self.resq.put(msg)

    def join(self, timeout=None):
        '''Added join method, for testing if thread is alive'''
        self._working.clear()
        threading.Thread.join(self, timeout)

    def _version_handshake(self):
        '''Sync function for negociating version, called after tcp connection'''
        versions = self._parse_response()
        if versions.count == 0:
            self._logger.warning('No versions reported')
            return False

        self._logger.debug(f'Received versions: {versions.data}')
        self._logger.debug(f'Requesting version {versions.data[0]}')
        self._conn.send(wcom.build_req(WispRequest.VERSION, versions.data[0]))
        ack = self._parse_response()
        if ack.code != WispResponse.OK:
            self._logger.error('Version handshake failed')
            return False
        self.state = State.Authentication
        return True

    def _parse_response(self):
        '''Parser for response messages'''
        data = []
        try:
            header = self._conn.recv(6)
            if len(header) < 6:
                self._logger.error('Header shorter than expected')
                raise Exception('Header too short')
            code = WispResponse.OK if header[:2].decode() == WispResponse.OK else WispResponse.ERROR
            length = struct.unpack('<I', header[2:6])[0]
            for _ in range(int(length)):
                data.append(wcom.parse_pkt_field(self._conn.recv(16).decode()))
            return WispResponse(code, data)
        except Exception as err:
            self._logger.error(f'Malformed response received')
            self._logger.debug(err)
            os._exit(1)
