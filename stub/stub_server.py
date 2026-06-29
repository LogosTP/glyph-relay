# SPDX-License-Identifier: Elastic-2.0
"""Local single-room stub standing in for the MUD until its endpoint exists.

Mirrors the live v1 server's behaviour as documented in the server notes: a
multi-step login (email -> password -> character name) followed by a shared room
that supports ``say``, ``emote``, ``who``, ``look`` and ``quit``. Runs plaintext
by default (matching v1) or with implicit TLS via ``--cert``/``--key`` (the
client's future default). Offers the M2 Telnet capabilities (NAWS, TTYPE, EOR, CHARSET, BINARY) and
requests the client's terminal type and UTF-8, recording what the client reports;
emits ``IAC GA`` after prompts so the client can exercise prompt detection.
"""
import argparse
import asyncio
import ssl

from glyph_relay.telnet import TelnetCodec, IAC, SB, SE, GA
from glyph_relay.negotiator import (
    Negotiator, NAWS, TTYPE, EOR, CHARSET, BINARY, GMCP,
    TTYPE_SEND, TTYPE_IS, CHARSET_REQUEST, CHARSET_ACCEPTED,
)

# A sample GMCP package pushed once the client has agreed to GMCP, so the relay
# exercises its parse+forward path end-to-end (#59).
GMCP_VITALS = (b"Char.Vitals "
               b'{"name":"Aria","level":"3","hp":"100","maxhp":"120","mp":"30"}')

GREETING = "Welcome to the MUD stub. (Nothing here is permanent.)\r\n"
EMAIL_PROMPT = "Enter your email (or any login name): "
PASSWORD_PROMPT = "Please enter your password: "
CONFIRM_PROMPT = "Please confirm your password: "
CHARACTER_PROMPT = "Create your character. Enter a character name: "


class Room:
    def __init__(self):
        self.members = {}

    def broadcast(self, line):
        data = (line + "\r\n").encode("utf-8")
        for writer in list(self.members.values()):
            writer.write(data)


def _prompt(writer, text):
    writer.write(text.encode("utf-8") + bytes([IAC, GA]))


def _record_client_caps(events, record):
    """Store the client's reported NAWS size / terminal type / charset."""
    if record is None:
        return
    for kind, payload in events:
        if kind != "subneg" or not payload:
            continue
        option, body = payload[0], payload[1:]
        if option == NAWS and len(body) >= 4:
            record["naws"] = (body[0] << 8 | body[1], body[2] << 8 | body[3])
        elif option == TTYPE and body[:1] == bytes([TTYPE_IS]):
            record["ttype"] = body[1:].decode("ascii", "replace")
        elif option == CHARSET and body[:1] == bytes([CHARSET_ACCEPTED]):
            record["charset"] = body[1:].decode("ascii", "replace")


async def handle(reader, writer, room, record=None):
    # Server-side accept policy: let the client enable NAWS/TTYPE/BINARY (we DO),
    # and we WILL EOR/CHARSET/BINARY.
    negotiator = Negotiator(
        local_options=(EOR, CHARSET, BINARY, GMCP),
        remote_options=(NAWS, TTYPE, BINARY),
    )
    codec = TelnetCodec(negotiator)
    state = "EMAIL"
    name = None
    password = None
    buf = ""
    try:
        writer.write(GREETING.encode("utf-8"))
        offers = b""
        for opt in (NAWS, TTYPE, BINARY):
            offers += negotiator.offer_remote(opt)
        for opt in (EOR, CHARSET, BINARY, GMCP):
            offers += negotiator.offer_local(opt)
        writer.write(offers)
        # Ask for the terminal type and request UTF-8 (pipelined; the client answers
        # these after it has agreed to TTYPE/CHARSET, since TCP preserves order).
        writer.write(bytes([IAC, SB, TTYPE, TTYPE_SEND, IAC, SE]))
        writer.write(bytes([IAC, SB, CHARSET, CHARSET_REQUEST]) + b";UTF-8"
                     + bytes([IAC, SE]))
        _prompt(writer, EMAIL_PROMPT)
        await writer.drain()
        while True:
            data = await reader.read(4096)
            if not data:
                break
            result = codec.receive(data)
            if result.to_send:
                writer.write(result.to_send)
                await writer.drain()
            _record_client_caps(result.events, record)
            buf += result.text.decode("utf-8", "replace")
            while "\n" in buf:
                raw, buf = buf.split("\n", 1)
                line = raw.strip("\r").strip()

                if state == "EMAIL":
                    if not line:
                        continue
                    state = "PASSWORD"
                    _prompt(writer, PASSWORD_PROMPT)
                    await writer.drain()
                elif state == "PASSWORD":
                    password = line
                    state = "CONFIRM"
                    _prompt(writer, CONFIRM_PROMPT)
                    await writer.drain()
                elif state == "CONFIRM":
                    # Mirror the live server: re-enter the password to confirm it.
                    if line == password:
                        state = "CHARACTER"
                        _prompt(writer, CHARACTER_PROMPT)
                    else:
                        writer.write(b"Passwords did not match.\r\n")
                        state = "PASSWORD"
                        _prompt(writer, PASSWORD_PROMPT)
                    await writer.drain()
                elif state == "CHARACTER":
                    if not line:
                        continue
                    name = line
                    state = "CONFIRM_CREATE"
                    _prompt(writer, "Create " + name + "? (yes/no): ")
                    await writer.drain()
                elif state == "CONFIRM_CREATE":
                    # Mirror the live server: confirm character creation.
                    if line.lower() in ("yes", "y"):
                        room.members[name] = writer
                        writer.write(("Welcome, " + name + "!\r\n").encode("utf-8"))
                        # If the client negotiated GMCP, push a sample package so the
                        # relay's out-of-band parse+forward path runs end-to-end (#59).
                        if negotiator.local_enabled(GMCP):
                            writer.write(bytes([IAC, SB, GMCP]) + GMCP_VITALS
                                         + bytes([IAC, SE]))
                        await writer.drain()
                        room.broadcast(name + " has entered the room.")
                        state = "PLAY"
                    else:
                        name = None
                        state = "CHARACTER"
                        _prompt(writer, CHARACTER_PROMPT)
                        await writer.drain()
                else:  # PLAY
                    if not line:
                        continue
                    if line == "quit":
                        writer.write(b"Goodbye.\r\n")
                        await writer.drain()
                        break
                    elif line == "who":
                        who = ", ".join(room.members) or "no one"
                        writer.write(("Online: " + who + ".\r\n").encode("utf-8"))
                        _prompt(writer, "")
                        await writer.drain()
                    elif line == "look":
                        who = ", ".join(room.members) or "no one"
                        writer.write(("In the room: " + who + ".\r\n").encode("utf-8"))
                        _prompt(writer, "")
                        await writer.drain()
                    elif line.startswith("emote "):
                        room.broadcast(name + " " + line[6:])
                    else:
                        said = line[4:] if line.startswith("say ") else line
                        room.broadcast(name + ": " + said)
    except (ConnectionResetError, OSError):
        # A peer that vanishes mid-read is normal here: the relay closes/reaps a
        # UserSession's socket abruptly, which surfaces as a reset on this handler.
        # Swallow it (CancelledError is not an OSError, so cancellation still
        # propagates) so a routine disconnect does not print an unhandled traceback.
        pass
    finally:
        if name and room.members.get(name) is writer:
            del room.members[name]
            room.broadcast(name + " has left the room.")
        writer.close()


async def main(argv=None):
    parser = argparse.ArgumentParser(description="MUD stub server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4000)
    parser.add_argument("--cert", default="stub/dev-cert.pem")
    parser.add_argument("--key", default="stub/dev-key.pem")
    parser.add_argument("--no-tls", action="store_true",
                        help="serve plaintext Telnet (matches the live v1 server)")
    args = parser.parse_args(argv)

    ssl_ctx = None
    if not args.no_tls:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(args.cert, args.key)

    room = Room()
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, room), args.host, args.port, ssl=ssl_ctx
    )
    addr = server.sockets[0].getsockname()
    print("stub listening on {} (tls={})".format(addr, not args.no_tls))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
