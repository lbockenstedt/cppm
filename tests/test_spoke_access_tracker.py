"""The Access Tracker supports recent history without changing dashboard counts."""
import asyncio
import time
from unittest.mock import MagicMock

from src.spoke import CPPMSpoke


def _run(coro):
    """Run a spoke command coroutine in a test event loop."""
    return asyncio.new_event_loop().run_until_complete(coro)


def test_access_tracker_without_window_keeps_active_session_query():
    """The dashboard's existing command stays active-only when no window is sent."""
    spoke = CPPMSpoke("cppm-1", {})
    spoke.queries.get_access_tracker = MagicMock(
        return_value={"status": "SUCCESS", "sessions": [], "total": 0}
    )
    spoke.queries.get_recent_access_tracker = MagicMock()

    result = _run(spoke.handle_command("CPPM_GET_ACCESS_TRACKER", {}))

    assert result["status"] == "SUCCESS"
    spoke.queries.get_access_tracker.assert_called_once_with(limit=200, offset=0)
    spoke.queries.get_recent_access_tracker.assert_not_called()


def test_access_tracker_window_bypasses_active_session_cache():
    """The optional time window selects recent history even if the active cache is warm."""
    spoke = CPPMSpoke("cppm-1", {})
    spoke._cache["CPPM_GET_ACCESS_TRACKER"] = {
        "status": "SUCCESS", "sessions": [{"id": "active-only"}], "total": 1,
    }
    spoke._cache_ts["CPPM_GET_ACCESS_TRACKER"] = time.time()
    spoke.queries.get_access_tracker = MagicMock()
    spoke.queries.get_recent_access_tracker = MagicMock(
        return_value={"status": "SUCCESS", "sessions": [{"id": "closed"}], "total": 1}
    )

    result = _run(spoke.handle_command(
        "CPPM_GET_ACCESS_TRACKER", {"lookback_hours": 24}
    ))

    assert result["sessions"] == [{"id": "closed"}]
    spoke.queries.get_access_tracker.assert_not_called()
    spoke.queries.get_recent_access_tracker.assert_called_once_with(
        limit=200, offset=0, lookback_hours=24, window_end=None
    )


def test_access_tracker_forwards_fixed_window_end_to_query():
    """Paged history commands reuse the hub-provided snapshot upper bound."""
    spoke = CPPMSpoke("cppm-1", {})
    spoke.queries.get_recent_access_tracker = MagicMock(
        return_value={"status": "SUCCESS", "sessions": [], "total": 0}
    )
    window_end = "2026-07-02T10:00:00Z"

    _run(spoke.handle_command("CPPM_GET_ACCESS_TRACKER", {
        "lookback_hours": 24, "window_end": window_end,
    }))

    spoke.queries.get_recent_access_tracker.assert_called_once_with(
        limit=200, offset=0, lookback_hours=24, window_end=window_end
    )
