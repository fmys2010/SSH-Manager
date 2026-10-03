# -*- coding: utf-8 -*-
"""Adaptive output decoding for CJK-capable SSH streams.

The decoder locks its encoding once at the head of a stream instead of
flipping mid-stream, which avoids the mojibake a one-way fallback produces
when a stream mixes ASCII with multi-byte text.

Decision rules while unlocked:

* pure ASCII is emitted immediately and does not lock anything;
* UTF-8 is preferred whenever it is merely *incomplete* (a multi-byte
  character split across chunks) - the common Linux case;
* GBK is chosen only when UTF-8 is definitively invalid;
* latin-1 is the last resort and can never fail.
"""

import codecs

_INCOMPLETE_REASONS = ("unexpected end of data", "incomplete multibyte sequence")


def _is_ascii(data):
    return all(byte < 0x80 for byte in data)


def _try_decode(data, encoding):
    """Return (text, status) with status in {"ok", "incomplete", "invalid"}."""
    try:
        return data.decode(encoding, "strict"), "ok"
    except UnicodeDecodeError as exc:
        if exc.reason in _INCOMPLETE_REASONS:
            return None, "incomplete"
        return None, "invalid"


class AdaptiveDecoder(object):
    """Incremental decoder: UTF-8 first, then GBK, then latin-1.

    ``encoding`` forces a single encoding (with ``errors="replace"``); when it
    is None the decoder auto-detects and locks the winner for the stream.
    """

    DETECT_WINDOW = 4096

    def __init__(self, encoding=None):
        self.encoding = encoding
        self._locked = None
        self._decoder = None
        self._pending = b""
        self._reset_state()

    # -- public API --------------------------------------------------------

    def decode(self, data):
        """Decode one chunk, resolving the encoding when the head allows it."""
        if not data:
            return ""
        if self._locked is not None:
            return self._decoder.decode(data)
        self._pending += data
        if _is_ascii(self._pending):
            text = self._pending.decode("ascii")
            self._pending = b""
            return text
        return self._decide()

    def flush(self):
        """Finalize the stream and return any trailing text."""
        if self._locked is None:
            if not self._pending:
                return ""
            text = self._pending.decode("latin-1")
            self._pending = b""
            return text
        return self._decoder.decode(b"", True)

    def reset(self):
        """Reset all state (call when starting a new stream)."""
        self._reset_state()

    # -- internals ---------------------------------------------------------

    def _reset_state(self):
        self._pending = b""
        if self.encoding:
            self._locked = self.encoding
            self._decoder = codecs.getincrementaldecoder(self.encoding)(errors="replace")
        else:
            self._locked = None
            self._decoder = None

    def _decide(self):
        pending = self._pending
        window = self.DETECT_WINDOW

        text, status = _try_decode(pending, "utf-8")
        if status == "ok":
            return self._lock("utf-8", text)
        if status == "incomplete":
            if len(pending) < window:
                return ""  # a UTF-8 character is split across chunks
            return self._lock_replace("utf-8", pending)

        gbk_text, gbk_status = _try_decode(pending, "gbk")
        if gbk_status == "ok":
            return self._lock("gbk", gbk_text)
        if gbk_status == "incomplete":
            if len(pending) < window:
                return ""  # a GBK character is split across chunks
            return self._lock_replace("gbk", pending)

        # Both strict candidates are definitively invalid: latin-1 never fails.
        return self._lock("latin-1", pending.decode("latin-1"))

    def _lock(self, name, text):
        self._locked = name
        self._decoder = codecs.getincrementaldecoder(name)(errors="replace")
        self._pending = b""
        return text

    def _lock_replace(self, name, pending):
        decoder = codecs.getincrementaldecoder(name)(errors="replace")
        text = decoder.decode(pending)
        self._locked = name
        self._decoder = decoder
        self._pending = b""
        return text
