# SPDX-License-Identifier: Elastic-2.0
"""Runtime entrypoint: build the relay for the selected mode and serve.

Config is read from the environment (see ``config.build_relay``); a few common knobs
are also exposed as CLI flags that override the environment. Secrets
(``GLYPH_ENROLL_SECRET``, ``SHARED_HMAC_KEY``, ``RELAY_ADMIN_SECRET``) are ENV-ONLY —
never CLI flags — so they don't land in a process listing.

    python3 -m glyph_relay --mud-host mud.example.com --mud-port 4000
    python3 -m glyph_relay --mode hosted --relay-target-allowlist servers.txt
"""
import argparse
import asyncio
import os
import signal

from .config import build_relay


def _env_from_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="python3 -m glyph_relay",
        description="Run the Glyph relay (self-host or hosted).")
    parser.add_argument("--mode", choices=("selfhost", "hosted"), default=None,
                        help="deployment mode (default: env RELAY_MODE or selfhost)")
    parser.add_argument("--host", help="relay bind host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, help="relay bind port (default 8765)")
    parser.add_argument("--mud-host", help="default MUD host (self-host target)")
    parser.add_argument("--mud-port", type=int, help="default MUD port")
    parser.add_argument("--tls", action="store_true", help="connect to the MUD over TLS")
    parser.add_argument("--relay-enroll-db", help="per-user enrollment registry path (#140)")
    parser.add_argument("--relay-target-allowlist",
                        help="host[:port]-per-line target allowlist (hosted SSRF policy)")
    parser.add_argument("--reaper-interval", type=float, default=60.0,
                        help="idle/revocation reaper period in seconds")
    args = parser.parse_args(argv)

    env = dict(os.environ)
    mapping = {
        "host": "RELAY_HOST", "port": "RELAY_PORT", "mud_host": "MUD_HOST",
        "mud_port": "MUD_PORT", "relay_enroll_db": "RELAY_ENROLL_DB",
        "relay_target_allowlist": "RELAY_TARGET_ALLOWLIST",
    }
    for attr, key in mapping.items():
        val = getattr(args, attr)
        if val is not None:
            env[key] = str(val)
    if args.tls:
        env["MUD_TLS"] = "1"
    mode = args.mode or env.get("RELAY_MODE", "selfhost")
    return mode, env, args.reaper_interval


async def _serve(mode, env, reaper_interval):
    relay = build_relay(mode, env)
    await relay.start()
    reaper = asyncio.create_task(relay.manager.run_reaper(interval=reaper_interval))
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, ValueError):
            pass  # e.g. on a platform without signal handlers
    print("glyph-relay [{0}] listening on {1}:{2}".format(mode, relay.host, relay.port))
    try:
        await stop.wait()
    finally:
        reaper.cancel()
        await relay.close()
        await relay.manager.close_all()


def main(argv=None):
    mode, env, reaper_interval = _env_from_args(argv)
    asyncio.run(_serve(mode, env, reaper_interval))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
