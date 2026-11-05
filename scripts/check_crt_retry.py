#!/usr/bin/env python3
"""Check the crt.sh retry shape against the failures crt.sh actually produces.

crt.sh failed the canary with `HTTP 502 after 2 attempts`. The source retried
once, waited 1 s, and gave up; the 502 comes back in under a second, so both
attempts landed inside the same short outage and the domain lookup reported
`error` while crt.sh recovered on its own a minute later. A third attempt, a
spaced backoff, and honouring `Retry-After` are what turn that into a lookup
that answers.

These checks pin the shape of that retry loop without any network:

    502, 502, 200      -> found, two pauses, three connections
    502 x3             -> error "... after 3 attempts", no pause after the last
    403 / 404          -> error at once, one connection, no pause
    200 with HTML      -> retried like a 5xx (an error page is not a miss)
    429 + Retry-After  -> the pause it asks for, capped so a page load survives
    a slow crt.sh      -> the budget stops a third attempt that cannot finish

Run from the repository root::

    python3 scripts/check_crt_retry.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests  # noqa: E402

from threattrove import core, sources  # noqa: E402
from threattrove.sources import CertificateTransparency  # noqa: E402

FAILED = []

CERTS = [{
    "name_value": "www.example.com\nexample.com",
    "issuer_name": "CN=R3,O=Let's Encrypt,C=US",
    "not_before": "2024-01-01T00:00:00",
    "not_after": "2024-04-01T00:00:00",
}]

IND = core.parse_indicator("example.com")


def check(label, got, want):
    ok = got == want
    print(("  ok   " if ok else "  FAIL ") + f"{label}: {got!r}"
          + ("" if ok else f" (want {want!r})"))
    if not ok:
        FAILED.append(label)
    return ok


class FakeResponse:
    """Just enough of ``requests.Response`` for the crt.sh code path."""

    def __init__(self, body=None, status: int = 200, headers=None,
                 not_json: bool = False):
        self._body = body
        self.status_code = status
        self.headers = headers or {}
        self._not_json = not_json

    @property
    def text(self) -> str:
        return "<html>error page</html>"

    def json(self):
        if self._not_json:
            raise ValueError("Expecting value: line 1 column 1 (char 0)")
        return self._body


def error_page(status: int = 200, headers=None) -> FakeResponse:
    """An HTML error page served with a 200, as crt.sh does when overloaded."""
    return FakeResponse(None, status=status, headers=headers, not_json=True)


class ScriptedSession:
    """Returns the queued answers in order and records what was asked."""

    def __init__(self, responses):
        self.queue = list(responses)
        self.calls = []

    def get(self, url, **kw):
        self.calls.append({"url": url, **kw})
        item = self.queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeTime:
    """A clock that only moves when the code sleeps or a request times out."""

    def __init__(self, start: float = 1000.0):
        self.now = start
        self.slept = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds):
        self.slept.append(round(float(seconds), 3))
        self.now += float(seconds)


def run(source, responses, session=None, clock=None):
    """Run ``_fetch`` against scripted answers.

    Returns ``(data, failure, slept, session)``; ``slept`` is the pause list the
    code asked for, without the test actually waiting.
    """
    session = session or ScriptedSession(responses)
    source.session = lambda: session  # type: ignore[method-assign]
    clock = clock or FakeTime()
    saved = sources.time
    sources.time = clock  # type: ignore[assignment]
    try:
        data, failure = source._fetch(IND)
    finally:
        sources.time = saved  # type: ignore[assignment]
    return data, failure, clock.slept, session


print("request shape")
src = CertificateTransparency()
_, _, _, sess = run(src, [FakeResponse(CERTS)])
call = sess.calls[0]
check("endpoint", call["url"], "https://crt.sh/")
check("domain is sent as q", call["params"].get("q"), "example.com")
check("JSON is requested", call["params"].get("output"), "json")
check("connect/read timeout", call["timeout"],
      (src._TIMEOUT[0], src._TIMEOUT[1]))
check("three attempts are allowed", src._ATTEMPTS, 3)

print("\na 502 that clears (the canary's failure)")
data, failure, slept, sess = run(src, [
    FakeResponse(status=502), FakeResponse(status=502), FakeResponse(CERTS)])
check("the third answer is used", failure is None and data == CERTS, True)
check("three connections", len(sess.calls), 3)
check("paused 2 s then 6 s", slept, [2.0, 6.0])

print("\na 502 that does not clear")
data, failure, slept, sess = run(src, [
    FakeResponse(status=502), FakeResponse(status=502), FakeResponse(status=502)])
check("status", failure.status, "error")
check("the note counts the attempts", failure.note, "HTTP 502 after 3 attempts")
check("three connections", len(sess.calls), 3)
check("no pause after the last attempt", slept, [2.0, 6.0])

print("\nour own bad request")
for status in (403, 404):
    _, failure, slept, sess = run(src, [FakeResponse(status=status)])
    check(f"HTTP {status} is final", failure.note, f"HTTP {status}")
    check(f"HTTP {status} asks once", (len(sess.calls), slept), (1, []))

print("\nan error page served as 200")
data, failure, slept, sess = run(src, [error_page(), error_page(), FakeResponse(CERTS)])
check("HTML in place of JSON is retried", failure is None and data == CERTS, True)
check("three connections", len(sess.calls), 3)
_, failure, _, _ = run(src, [error_page(), error_page(), error_page()])
check("bad JSON is named, not reported as a miss", failure.note,
      "bad JSON (error page, not a certificate list) after 3 attempts")

print("\nRetry-After")
_, _, slept, _ = run(src, [
    FakeResponse(status=429, headers={"Retry-After": "30"}), FakeResponse(CERTS)])
check("a long Retry-After is capped at 15 s", slept, [15.0])
_, _, slept, _ = run(src, [
    FakeResponse(status=503, headers={"Retry-After": "8"}), FakeResponse(CERTS)])
check("a short Retry-After outranks the 2 s backoff", slept, [8.0])
_, _, slept, _ = run(src, [
    FakeResponse(status=429, headers={"Retry-After": "later"}), FakeResponse(CERTS)])
check("an unparseable Retry-After falls back to the backoff", slept, [2.0])

print("\na slow crt.sh must not outlast a page load")


class TimeoutSession:
    """Every request reads for its whole timeout, then raises."""

    def __init__(self, clock):
        self.clock = clock
        self.calls = []

    def get(self, url, **kw):
        self.calls.append(kw)
        self.now_served = kw["timeout"][1]
        self.clock.now += kw["timeout"][1]
        raise requests.Timeout("read timed out")


clock = FakeTime()
slow = TimeoutSession(clock)
_, failure, slept, sess = run(src, [], session=slow, clock=clock)
check("the budget stops the hopeless third attempt", len(sess.calls), 2)
check("the note only claims the attempts made",
      failure.note.endswith("after 2 attempts"), True)
spent = round(clock.now - 1000.0, 1)
check("two read windows and one backoff cost 32 s", spent, 32.0)
check("time spent stays inside the budget", spent <= src._BUDGET, True)
check("the budget is below the 45 s engine deadline",
      src._BUDGET + src._MIN_SLICE <= 45.0, True)

print("\nlookup() on a recovered 502")
src2 = CertificateTransparency()
sess2 = ScriptedSession([FakeResponse(status=502), FakeResponse(status=502),
                         FakeResponse(CERTS)])
src2.session = lambda: sess2  # type: ignore[method-assign]
clock2 = FakeTime()
saved = sources.time
sources.time = clock2  # type: ignore[assignment]
try:
    result = src2.lookup(IND)
finally:
    sources.time = saved  # type: ignore[assignment]
check("the lookup answers instead of failing", result.status, "found")
check("hostnames are read from the recovered answer",
      result.detail["hostnames"], ["example.com", "www.example.com"])

print()
if FAILED:
    print(f"FAILED: {len(FAILED)} check(s): " + ", ".join(FAILED))
    sys.exit(1)
print("all crt.sh retry checks passed")
