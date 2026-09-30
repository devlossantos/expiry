import logging
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from expiry.scheduler import configure_logging


def test_log_lines_format_in_configured_timezone():
    formatter = configure_logging(ZoneInfo("Europe/Dublin"))
    try:
        record = logging.LogRecord("expiry.daemon", logging.INFO, __file__, 1, "check: due=%d sent=%d", (2, 1),
                                   None)
        record.created = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc).timestamp()
        line = formatter.format(record)  # used to raise: converter bound as a method
        assert line.startswith("2026-07-01 13:00:00")  # IST = UTC+1 in summer
        assert line.endswith("expiry.daemon: check: due=2 sent=1")
    finally:
        logging.getLogger().handlers.clear()
