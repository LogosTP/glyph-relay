# SPDX-License-Identifier: Elastic-2.0
"""RFC 1143 Q-method Telnet option negotiator for the MUD client.

Pure: no I/O. Owns the per-option accept policy, the Q-method state machine, and
the capability values used to build subnegotiations (window size, terminal type,
charset). `TelnetCodec` feeds it received negotiations/subnegotiations and emits
the reply bytes it returns.

Constants below are RFC-fixed and intentionally mirror the framing constants in
telnet.py. NOTE: `EOR = 25` here is the Telnet OPTION (END-OF-RECORD negotiation,
RFC 885), NOT the IAC EOR marker byte 239 defined in telnet.py.

GMCP (Generic MUD Communication Protocol, option 201) is accepted here so the relay
can carry the MUD's out-of-band data to phones (#59). Enabling it emits the standard
`Core.Hello` + `Core.Supports.Set` handshake so the MUD starts streaming packages;
parsing those packages into structured events is `structured.py` (still no I/O here:
this only builds the bytes, the codec/transport sends them).
"""
import json
import os

# Telnet command bytes we emit.
IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240

# Options (RFC 856/1073/1091/885/2066).
BINARY = 0
SGA = 3
TTYPE = 24
EOR = 25          # END-OF-RECORD *option* (not the 239 marker byte)
NAWS = 31
CHARSET = 42
GMCP = 201        # Generic MUD Communication Protocol (out-of-band JSON).

# GMCP handshake: who we are, and the package families the relay parses+forwards.
# Core.Supports.Set is a JSON array of "Module version" strings (#59).
GMCP_CLIENT = "Glyph"
GMCP_VERSION = "1"
GMCP_SUPPORTS = ["Char 1", "Room 1", "Comm 1"]

# TTYPE subcommands (RFC 1091).
TTYPE_IS = 0
TTYPE_SEND = 1

# CHARSET subcommands (RFC 2066).
CHARSET_REQUEST = 1
CHARSET_ACCEPTED = 2
CHARSET_REJECTED = 3

# RFC 1143 Q-method states (per option, per side).
_NO, _YES, _WANTNO, _WANTNO_OPP, _WANTYES, _WANTYES_OPP = range(6)


def _u16(n):
    return bytes([(n >> 8) & 0xFF, n & 0xFF])


def _escape_sb(data):
    """Double any 0xFF (IAC) inside a subnegotiation payload, per RFC 855."""
    return data.replace(b"\xff", b"\xff\xff")


def default_term_types():
    """MTTS-style cycle derived from the environment's TERM."""
    term = os.environ.get("TERM", "")
    first = term.upper() if term else "XTERM-256COLOR"
    return [first, "XTERM", "MTTS 13"]   # 13 = ANSI(1) + UTF-8(4) + 256-color(8)


class Negotiator:
    def __init__(self, local_options=None, remote_options=None,
                 term_types=None, charset="UTF-8", cols=80, rows=24):
        self.local_ok = set(local_options if local_options is not None
                            else (BINARY, TTYPE, NAWS))
        self.remote_ok = set(remote_options if remote_options is not None
                             else (BINARY, EOR, CHARSET, GMCP))
        self.term_types = list(term_types) if term_types else default_term_types()
        self.charset = charset
        self.set_window_size(cols, rows)
        self._us = {}    # option -> Q-method state for OUR (WILL) side
        self._him = {}   # option -> Q-method state for the REMOTE (WILL) side
        self._ttype_index = 0

    # --- introspection ---
    def local_enabled(self, option):
        return self._us.get(option, _NO) == _YES

    def remote_enabled(self, option):
        return self._him.get(option, _NO) == _YES

    # --- capabilities ---
    def set_window_size(self, cols, rows):
        self.cols = max(1, min(65535, int(cols)))
        self.rows = max(1, min(65535, int(rows)))

    def naws_sb(self):
        payload = _escape_sb(_u16(self.cols) + _u16(self.rows))
        return bytes([IAC, SB, NAWS]) + payload + bytes([IAC, SE])

    def _gmcp_sb(self, message):
        """One GMCP subnegotiation frame carrying ``"Package.Name <json>"`` (RFC 855
        IAC-escaped). GMCP rides inside Telnet SB just like TTYPE/CHARSET above."""
        payload = _escape_sb(message.encode("utf-8"))
        return bytes([IAC, SB, GMCP]) + payload + bytes([IAC, SE])

    def gmcp_hello(self):
        """The opening GMCP handshake: ``Core.Hello`` (client id/version) followed by
        ``Core.Supports.Set`` advertising the package families the relay parses. Pure —
        returns the bytes; the connection writes them once we agree to GMCP (#59)."""
        hello = json.dumps({"client": GMCP_CLIENT, "version": GMCP_VERSION},
                           separators=(",", ":"))
        supports = json.dumps(GMCP_SUPPORTS, separators=(",", ":"))
        return (self._gmcp_sb("Core.Hello " + hello)
                + self._gmcp_sb("Core.Supports.Set " + supports))

    # --- proactive offers (used by the stub / future client initiation) ---
    def offer_local(self, option):
        if self._us.get(option, _NO) == _NO:
            self._us[option] = _WANTYES
            return bytes([IAC, WILL, option])
        return b""

    def offer_remote(self, option):
        if self._him.get(option, _NO) == _NO:
            self._him[option] = _WANTYES
            return bytes([IAC, DO, option])
        return b""

    # --- received negotiation ---
    def receive_negotiation(self, verb, option):
        if verb == WILL:
            return self._recv_will(option)
        if verb == WONT:
            return self._recv_wont(option)
        if verb == DO:
            return self._recv_do(option)
        if verb == DONT:
            return self._recv_dont(option)
        return b""

    def _recv_will(self, option):
        state = self._him.get(option, _NO)
        if state == _NO:
            if option in self.remote_ok:
                self._him[option] = _YES
                reply = bytes([IAC, DO, option])
                if option == GMCP:
                    # Kick off GMCP: most MUDs only stream packages once they see our
                    # Core.Hello + Core.Supports.Set advertising what we understand.
                    reply += self.gmcp_hello()
                return reply
            return bytes([IAC, DONT, option])
        if state == _WANTNO:
            self._him[option] = _NO
        elif state == _WANTNO_OPP:
            self._him[option] = _YES
        elif state == _WANTYES:
            self._him[option] = _YES
        elif state == _WANTYES_OPP:
            self._him[option] = _WANTNO
            return bytes([IAC, DONT, option])
        return b""

    def _recv_wont(self, option):
        state = self._him.get(option, _NO)
        if state == _YES:
            self._him[option] = _NO
            return bytes([IAC, DONT, option])
        if state == _WANTNO:
            self._him[option] = _NO
        elif state == _WANTNO_OPP:
            self._him[option] = _WANTYES
            return bytes([IAC, DO, option])
        elif state in (_WANTYES, _WANTYES_OPP):
            self._him[option] = _NO
        return b""

    def _recv_do(self, option):
        state = self._us.get(option, _NO)
        if state == _NO:
            if option in self.local_ok:
                self._us[option] = _YES
                reply = bytes([IAC, WILL, option])
                if option == NAWS:
                    reply += self.naws_sb()
                return reply
            return bytes([IAC, WONT, option])
        if state == _WANTNO:
            self._us[option] = _NO
        elif state == _WANTNO_OPP:
            self._us[option] = _YES
        elif state == _WANTYES:
            self._us[option] = _YES
            if option == NAWS:
                return self.naws_sb()
        elif state == _WANTYES_OPP:
            self._us[option] = _WANTNO
            return bytes([IAC, WONT, option])
        return b""

    def _recv_dont(self, option):
        state = self._us.get(option, _NO)
        if state == _YES:
            self._us[option] = _NO
            return bytes([IAC, WONT, option])
        if state == _WANTNO:
            self._us[option] = _NO
        elif state == _WANTNO_OPP:
            self._us[option] = _WANTYES
            return bytes([IAC, WILL, option])
        elif state in (_WANTYES, _WANTYES_OPP):
            self._us[option] = _NO
        return b""

    # --- received subnegotiation ---
    def receive_subneg(self, payload):
        if not payload:
            return b""
        option, body = payload[0], payload[1:]
        if option == TTYPE and body[:1] == bytes([TTYPE_SEND]):
            return self._ttype_is()
        if option == CHARSET and body[:1] == bytes([CHARSET_REQUEST]):
            return self._charset_reply(body[1:])
        return b""

    def _ttype_is(self):
        idx = min(self._ttype_index, len(self.term_types) - 1)
        name = self.term_types[idx]
        if self._ttype_index < len(self.term_types) - 1:
            self._ttype_index += 1
        payload = _escape_sb(bytes([TTYPE_IS]) + name.encode("ascii", "replace"))
        return bytes([IAC, SB, TTYPE]) + payload + bytes([IAC, SE])

    def _charset_reply(self, request):
        # request = <sep> name [<sep> name ...], optionally prefixed "[TTABLE]<ver>".
        if request[:8] == b"[TTABLE]":
            request = request[9:]   # skip "[TTABLE]" (8) + 1 version octet
        if not request:
            return bytes([IAC, SB, CHARSET, CHARSET_REJECTED, IAC, SE])
        sep = request[:1]
        wanted = self.charset.upper().encode("ascii", "replace")
        for name in request[1:].split(sep):
            if name.upper() == wanted:
                payload = _escape_sb(bytes([CHARSET_ACCEPTED]) + name)
                return bytes([IAC, SB, CHARSET]) + payload + bytes([IAC, SE])
        return bytes([IAC, SB, CHARSET, CHARSET_REJECTED, IAC, SE])
