# SPDX-License-Identifier: Elastic-2.0
"""MUD login state machine extracted from the Glyph client's app.py.

The relay drives one connection per user session and must answer the live MUD's
multi-step login prompt sequence (login/email -> password -> character name).
``LoginFlow`` matches server prompts to configured answers; matching is
deliberately conservative so a banner/MOTD/chat line that merely contains the
word "login"/"password"/"character" never triggers a credential send on the
plaintext wire.

Pure: no I/O. ``sessions.UserSession`` feeds received text + codec prompt events
in and gets back the (source, value, display) tuples to send.
"""
import re

# Reset the reconnect backoff only after a connection stayed up at least this
# long, so a server that accepts then instantly drops still ramps its backoff.
HEALTHY_SESSION_SECONDS = 5.0


# A trailing line "looks like a prompt" if it ends in one of these terminators.
_PROMPT_END_RE = re.compile(r"[:?>#]\s*$")


def _looks_like_prompt(text):
    return bool(_PROMPT_END_RE.search(text))


# --- Login state machine -------------------------------------------------

# Default prompt patterns for each login step (case-insensitive, word-anchored).
DEFAULT_LOGIN_PATTERNS = {
    "email": r"\b(?:e-?mail|login|user(?:name)?|account)\b",
    "password": r"\b(?:password|passphrase)\b",
    "confirm": r"\bconfirm\b.*\bpass(?:word|phrase)\b",
    "character": r"\bcharacter\b",
    "confirm_create": r"\bcreate\b.*\byes\s*/\s*no\b",
}


class LoginStep:
    """One step of the login sequence: when ``pattern`` is seen, send ``value``."""

    def __init__(self, source, pattern, value, secret=False, optional=False):
        self.source = source
        self.re = re.compile(pattern, re.I)
        self.value = value
        self.secret = secret
        # Optional steps are skipped (not blocking) when their prompt never
        # appears -- e.g. a server build that doesn't confirm the password.
        self.optional = optional


def default_login_steps(email, password, character):
    """Build the standard email -> password -> character login sequence.

    Steps whose value is None are skipped by ``LoginFlow``, so a partially
    configured login (e.g. only ``--character``) still works -- the rest is typed
    manually by whoever is driving.
    """
    return [
        LoginStep("login", DEFAULT_LOGIN_PATTERNS["email"], email),
        LoginStep("login", DEFAULT_LOGIN_PATTERNS["password"], password, secret=True),
        # Some server builds confirm the password by asking for it again. Optional:
        # skipped when the server doesn't, re-sends the same value when it does.
        LoginStep("login", DEFAULT_LOGIN_PATTERNS["confirm"], password,
                  secret=True, optional=True),
        LoginStep("login", DEFAULT_LOGIN_PATTERNS["character"], character),
        # Some builds confirm character creation: "Create <name>? (yes/no)". Optional;
        # auto-answered "yes" only when we also auto-sent the character name.
        LoginStep("login", DEFAULT_LOGIN_PATTERNS["confirm_create"],
                  "yes" if character is not None else None, optional=True),
    ]


class LoginFlow:
    """Drive a multi-step login by matching server prompts to configured answers.

    Stateful per connection. Feed received ``text`` (and optional codec
    ``events``); get back a list of ``(source, value, display)`` tuples to send
    for any prompt recognized. At most one step fires per prompt, in order; a
    secret step's display is masked. Matching only happens at a prompt boundary
    (a GA/EOR event, or a trailing line ending in a prompt terminator).
    """

    def __init__(self, steps):
        self.steps = [s for s in steps if s.value is not None]
        self._idx = 0
        self._buf = ""
        # Command-gate state (see the `password_sent` property). `_sent_secret`:
        # a password/confirm value has gone out. `_at_credential_prompt`: the most
        # recent prompt is a password/confirm prompt, where a command must never land.
        self._sent_secret = False
        self._at_credential_prompt = False

    def feed(self, text, events=None):
        out = []
        self._buf += text
        if len(self._buf) > 8192:
            self._buf = self._buf[-8192:]

        prompt_event = bool(events) and any(kind == "prompt" for kind, _ in events)
        # Only the trailing, un-newlined segment is a prompt candidate; anything
        # before the last newline is completed output (banner/MOTD/chat), not a
        # prompt, and must never trigger a credential send.
        tail = self._buf.rsplit("\n", 1)[-1]
        if not (prompt_event or _looks_like_prompt(tail)):
            return out

        # Classify this prompt for the command gate: a credential prompt is one that
        # matches a secret (password/confirm) step's pattern. A command must never land
        # at one of these (it would become the password or its confirmation).
        self._at_credential_prompt = any(
            s.secret and s.re.search(tail) for s in self.steps)

        while self._idx < len(self.steps):
            step = self.steps[self._idx]
            if step.re.search(tail):
                display = "********" if step.secret else step.value
                out.append((step.source, step.value, display))
                if step.secret:
                    self._sent_secret = True
                self._idx += 1
                self._buf = ""   # consume the prompt; next step waits for the next one
                break
            # An optional step whose prompt never arrived: if a *later* step matches
            # this prompt instead, skip the optional step and try the next one.
            if step.optional and any(
                    self.steps[j].re.search(tail)
                    for j in range(self._idx + 1, len(self.steps))):
                self._idx += 1
                continue
            # The trailing prompt is not the one this step is waiting for; stop.
            break
        return out

    @property
    def done(self):
        return self._idx >= len(self.steps)

    @property
    def password_sent(self):
        # Command gate. Open once a password has been sent AND the most recent prompt
        # is NOT a credential (password/confirm) prompt -- so a queued command can never
        # leak in as the password or its confirmation, yet the gate still opens on any
        # post-credential prompt: the character prompt, the create-confirm prompt, OR a
        # reconnect that drops straight into the world with no confirm/character prompt.
        # (Keying this off the login-step index left the gate stuck closed on that
        # reconnect path, since the optional confirm step was never fired or skipped.)
        return self._sent_secret and not self._at_credential_prompt
