# SPDX-License-Identifier: Elastic-2.0
"""Asyncio transport: wraps the Telnet codec around a (TLS) socket."""
import asyncio
import codecs
import ssl

from .telnet import TelnetCodec
from .negotiator import Negotiator, NAWS


def make_ssl_context(verify, cafile=None, cadata=None):
    # Passing cafile/cadata pins trust to exactly that CA (system roots are NOT
    # loaded), which is what we want for a MUD's private root CA. With verify
    # on, the chain and hostname are both checked.
    ctx = ssl.create_default_context(cafile=cafile, cadata=cadata)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class Connection:
    def __init__(self, host, port, use_tls=True, verify=False, raw_logger=None,
                 negotiator=None, cafile=None, cadata=None, connect_host=None):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.verify = verify
        self.cafile = cafile
        self.cadata = cadata
        # §2.2: the address actually dialed. When None, dial ``host`` (self-host,
        # unchanged). When set (the relay's pinned IP), dial THAT while TLS SNI/cert
        # verification still uses ``host`` -- so a DNS rebind cannot redirect us.
        self.connect_host = connect_host
        self.raw_logger = raw_logger
        self._reader = None
        self._writer = None
        self._negotiator = negotiator if negotiator is not None else Negotiator()
        self._codec = TelnetCodec(self._negotiator)
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    async def connect(self):
        ssl_ctx = (make_ssl_context(self.verify, self.cafile, self.cadata)
                   if self.use_tls else None)
        dial = self.connect_host or self.host
        kwargs = {}
        if ssl_ctx is not None and dial != self.host:
            # Dialing the pinned IP: keep SNI + cert hostname = the original host.
            kwargs["server_hostname"] = self.host
        self._reader, self._writer = await asyncio.open_connection(
            dial, self.port, ssl=ssl_ctx, **kwargs
        )

    async def receive(self):
        while True:
            data = await self._reader.read(4096)
            if not data:
                return
            if self.raw_logger:
                self.raw_logger("RECV", data)
            result = self._codec.receive(data)
            if result.to_send:
                self._writer.write(result.to_send)
                await self._writer.drain()
            yield self._decoder.decode(result.text), result.events

    async def send(self, line):
        payload = TelnetCodec.escape(line.encode("utf-8")) + b"\r\n"
        if self.raw_logger:
            self.raw_logger("SENT", payload)
        self._writer.write(payload)
        await self._writer.drain()

    async def update_window_size(self, cols, rows):
        self._negotiator.set_window_size(cols, rows)
        if self._writer is None or not self._negotiator.local_enabled(NAWS):
            return
        frame = self._negotiator.naws_sb()
        if self.raw_logger:
            self.raw_logger("SENT", frame)
        try:
            self._writer.write(frame)
            await self._writer.drain()
        except OSError:
            pass  # socket dying; the supervisor will reconnect

    async def close(self):
        if self._writer is not None:
            self._writer.close()
