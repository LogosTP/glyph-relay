# SPDX-License-Identifier: Elastic-2.0
"""Sans-IO Telnet codec for the MUD client.

Pure: bytes in -> Received(text, events, to_send). No I/O. Option negotiation and
subnegotiation are delegated to a Negotiator (RFC 1143 Q-method, M2); GMCP
acceptance is M3.
"""
from collections import namedtuple
from .negotiator import Negotiator

# Telnet commands (RFC 854) and the EOR prompt marker (RFC 885).
IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
GA = 249
SE = 240
EOR = 239

_NORMAL, _IAC, _NEG, _SB, _SB_IAC = range(5)

Received = namedtuple("Received", "text events to_send")


class TelnetCodec:
    def __init__(self, negotiator=None):
        self._state = _NORMAL
        self._verb = 0
        self._sb = bytearray()
        self._negotiator = negotiator if negotiator is not None else Negotiator()

    @staticmethod
    def escape(data):
        return data.replace(bytes([IAC]), bytes([IAC, IAC]))

    def receive(self, data):
        text = bytearray()
        events = []
        out = bytearray()
        for b in data:
            if self._state == _NORMAL:
                if b == IAC:
                    self._state = _IAC
                else:
                    text.append(b)
            elif self._state == _IAC:
                if b == IAC:
                    text.append(IAC)
                    self._state = _NORMAL
                elif b in (WILL, WONT, DO, DONT):
                    self._verb = b
                    self._state = _NEG
                elif b == SB:
                    self._sb = bytearray()
                    self._state = _SB
                elif b == GA:
                    events.append(("prompt", "GA"))
                    self._state = _NORMAL
                elif b == EOR:
                    events.append(("prompt", "EOR"))
                    self._state = _NORMAL
                else:
                    self._state = _NORMAL  # NOP / unknown 2-byte command
            elif self._state == _NEG:
                out += self._negotiator.receive_negotiation(self._verb, b)
                self._state = _NORMAL
            elif self._state == _SB:
                if b == IAC:
                    self._state = _SB_IAC
                else:
                    self._sb.append(b)
            elif self._state == _SB_IAC:
                if b == SE:
                    payload = bytes(self._sb)
                    events.append(("subneg", payload))
                    out += self._negotiator.receive_subneg(payload)
                    self._state = _NORMAL
                elif b == IAC:
                    self._sb.append(IAC)
                    self._state = _SB
                else:
                    # IAC followed by some other byte inside SB: RFC 855 leaves
                    # this undefined. Preserve the literal IAC (0xFF) rather than
                    # silently dropping it, mirroring the IAC IAC handling above.
                    self._sb.append(IAC)
                    self._sb.append(b)
                    self._state = _SB
        return Received(bytes(text), events, bytes(out))
