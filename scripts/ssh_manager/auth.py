# -*- coding: utf-8 -*-
"""Authentication helpers: host-key policy, private-key discovery and loading.

Design notes
------------
* Key authentication is opt-in: nothing here runs unless the caller passed
  ``--key``. Without it the manager behaves exactly like the password-only v1.
* The CLI resolves and validates the private key (it owns the terminal, so it
  can prompt for a passphrase); the daemon then reloads the same file to
  perform the actual SSH handshake.
* The passphrase is never logged and never appears in an exception message.
"""

import base64
import getpass
import os
import stat
import struct

import paramiko

# Sentinel for a bare ``--key`` (discover keys and allow ssh-agent).
KEY_DISCOVER = "__discover__"
DEFAULT_KEY_NAMES = ("id_ed25519", "id_rsa", "id_ecdsa")

_OPENSSH_HEADER = b"-----BEGIN OPENSSH PRIVATE KEY-----"
_OPENSSH_FOOTER = b"-----END OPENSSH PRIVATE KEY-----"
_OPENSSH_MAGIC = b"openssh-key-v1\x00"


class AuthError(Exception):
    """Raised when no usable credential can be assembled."""


# -- host keys -----------------------------------------------------------------

def configure_host_keys(client, known_hosts=None, no_host_key_check=False):
    """Apply the host-key policy to a client. Returns the effective mode."""
    if no_host_key_check:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return "disabled"
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.load_system_host_keys()
    if known_hosts:
        client.load_host_keys(os.path.expanduser(known_hosts))
    return "strict"


def unknown_host_hint(host, port):
    """Actionable message shown when strict host-key checking rejects a host."""
    return (
        "host key verification failed for %s:%s. Add the host key to known_hosts, e.g.\n"
        "  ssh-keyscan -p %s %s >> ~/.ssh/known_hosts\n"
        "or pass --known-hosts <file>, or explicitly disable the check with "
        "--no-host-key-check." % (host, port, port, host)
    )


# -- private keys --------------------------------------------------------------

def default_ssh_dir():
    return os.path.join(os.path.expanduser("~"), ".ssh")


def discover_key_paths(ssh_dir=None):
    """Existing default private keys, in preference order."""
    directory = ssh_dir or default_ssh_dir()
    found = []
    for name in DEFAULT_KEY_NAMES:
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            found.append(path)
    return found


def key_is_encrypted(path):
    """True when the private key file is passphrase-protected.

    Handles both the OpenSSH ``openssh-key-v1`` container (where the cipher
    name is part of the structure) and legacy PEM files (``DEK-Info`` header).
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return False
    if _OPENSSH_HEADER in data:
        try:
            body = data.split(_OPENSSH_HEADER, 1)[1].split(_OPENSSH_FOOTER, 1)[0]
            raw = base64.b64decode(b"".join(body.split()))
            if not raw.startswith(_OPENSSH_MAGIC):
                return False
            offset = len(_OPENSSH_MAGIC)

            def read_string(position):
                (length,) = struct.unpack(">I", raw[position:position + 4])
                start = position + 4
                return raw[start:start + length], start + length

            cipher, _ = read_string(offset)
            return cipher != b"none"
        except (ValueError, struct.error, IndexError):
            return False
    head = data[:200]
    return b"ENCRYPTED" in head or b"DEK-Info" in head


def key_permission_warning(path):
    """Return a warning string when a POSIX key is group/world readable."""
    if os.name != "posix":
        return None
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return None
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        return "%s is readable by other users (mode %o); consider chmod 600" % (
            path, mode)
    return None


def load_private_key(path, passphrase=None):
    """Load a private key file, raising AuthError with a readable message."""
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")  # paramiko expects bytes
    try:
        return paramiko.PKey.from_path(path, passphrase)
    except paramiko.PasswordRequiredException:
        raise AuthError("%s requires a passphrase" % path)
    except Exception as exc:  # cryptography raises bare ValueError on bad keys
        detail = str(exc).splitlines()[0][:160]
        if passphrase is not None:
            raise AuthError("%s: wrong passphrase or unsupported key (%s)" % (path, detail))
        raise AuthError("%s could not be loaded (%s)" % (path, detail))


def resolve_private_key(key_arg, passphrase=None, prompt=None, ssh_dir=None):
    """Resolve ``--key`` into a concrete (path, passphrase, notes) triple.

    ``prompt`` is an optional callable ``prompt(path) -> str|None`` used when an
    encrypted key is found and no passphrase was supplied. Callers pass a
    terminal prompt, or None in non-interactive contexts (then the candidate is
    skipped and the next one is tried).
    """
    if key_arg is None:
        return None, None, []

    if key_arg == KEY_DISCOVER:
        candidates = discover_key_paths(ssh_dir)
        if not candidates:
            # Nothing on disk: fall back to ssh-agent only.
            return None, None, [
                "no private key found in %s (looked for %s); will try ssh-agent" % (
                    ssh_dir or default_ssh_dir(), ", ".join(DEFAULT_KEY_NAMES))]
    else:
        path = os.path.expanduser(key_arg)
        if not os.path.isfile(path):
            raise AuthError("private key not found: %s" % path)
        candidates = [path]

    notes = []
    current_passphrase = passphrase
    for path in candidates:
        warning = key_permission_warning(path)
        if warning:
            notes.append(warning)
        encrypted = key_is_encrypted(path)
        if encrypted and not current_passphrase and prompt is not None:
            supplied = prompt(path)
            if supplied:
                current_passphrase = supplied
        if encrypted and not current_passphrase:
            notes.append("%s: passphrase required (skipped)" % path)
            continue
        try:
            load_private_key(path, current_passphrase if encrypted else None)
        except AuthError as exc:
            notes.append(str(exc))
            continue
        return path, (current_passphrase if encrypted else None), notes

    raise AuthError("no usable private key:\n  " + "\n  ".join(notes))


def terminal_prompt(path):
    """Interactive passphrase prompt; returns None when there is no terminal."""
    try:
        if not os.isatty(0):
            return None
    except (AttributeError, ValueError):
        return None
    try:
        return getpass.getpass("Passphrase for %s: " % path)
    except (EOFError, KeyboardInterrupt):
        return None
