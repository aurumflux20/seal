"""Session-level guard: a run where nothing executed is not a pass.

Every test in this suite is gated on SEAL_DSN, because the properties being
tested (exactly-once admission under real concurrency) are meaningless without
a real Postgres. That gating is correct, but it has a sharp edge: with no DSN
set, pytest skips all ~179 tests and still exits 0. A green exit code that
proves nothing is precisely the failure mode this project exists to prevent,
and CI would report it as success if the postgres service ever failed to come
up or the env var were renamed.

So: always say loudly when nothing ran, and in CI (SEAL_REQUIRE_TESTS=1) make
it a hard failure. Locally it stays a warning, so working on docs without a
database is not blocked.
"""
import os
import sys


def pytest_sessionfinish(session, exitstatus):
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is None:
        return
    passed = len(reporter.stats.get("passed", []))
    skipped = len(reporter.stats.get("skipped", []))
    failed = len(reporter.stats.get("failed", []))

    if passed == 0 and failed == 0 and skipped > 0:
        msg = (f"\n  {skipped} test(s) skipped, 0 executed. "
               f"This is NOT a passing run — it proves nothing.\n"
               f"  Set SEAL_DSN to a live Postgres to actually run the suite.\n")
        print(msg, file=sys.stderr)
        if os.environ.get("SEAL_REQUIRE_TESTS") == "1":
            print("  SEAL_REQUIRE_TESTS=1 — failing the run.", file=sys.stderr)
            session.exitstatus = 3
