"""Phase 7.8: recurrence-forecast pure-math tests (no DB)."""
import datetime

from shadowtracer_ml.forecast import collapse_bursts, forecast_from_times, MIN_HISTORY

UTC = datetime.timezone.utc


def _t(day, hour=12):
    return datetime.datetime(2026, 1, 1, hour, tzinfo=UTC) + datetime.timedelta(days=day)


def test_collapse_bursts_merges_close_occurrences():
    base = datetime.datetime(2026, 1, 1, tzinfo=UTC)
    burst = [base + datetime.timedelta(minutes=m) for m in range(10)]   # 10 within 10 min -> 1 event
    assert collapse_bursts(burst) == [base]
    spread = [base + datetime.timedelta(days=d) for d in range(5)]      # 5 daily -> 5 events
    assert len(collapse_bursts(spread)) == 5


def test_not_enough_history_returns_none():
    assert forecast_from_times([_t(0), _t(2), _t(4)]) is None          # only 3 events
    # a big burst is still one event -> not enough
    base = datetime.datetime(2026, 1, 1, tzinfo=UTC)
    assert forecast_from_times([base + datetime.timedelta(minutes=m) for m in range(50)]) is None


def test_regular_series_forecasts_a_window_after_the_last():
    f = forecast_from_times([_t(7 * i) for i in range(8)])             # weekly, 8 events
    assert f["occurrences"] == 8
    assert f["raw_occurrences"] == 8
    assert f["predicted_start"] > _t(49)                              # window is in the future of last
    assert f["predicted_end"] >= f["predicted_start"]
    # perfectly regular weekly (>=8 events, low dispersion) -> high confidence, concentrated hour-of-week
    assert f["confidence"] == "high"
    assert f["hour_of_week_concentration"] == 1.0                      # all on the same weekday/hour
    assert f["model_version"].startswith("7.8")


def test_irregular_series_has_lower_confidence_and_wider_window():
    reg = forecast_from_times([_t(d) for d in (0, 7, 14, 21, 28, 35, 42, 49)])
    irr = forecast_from_times([_t(d) for d in (0, 1, 9, 11, 30, 31, 60, 95)])
    reg_w = (reg["predicted_end"] - reg["predicted_start"]).total_seconds()
    irr_w = (irr["predicted_end"] - irr["predicted_start"]).total_seconds()
    assert irr_w > reg_w                                              # irregular gaps -> wider IQR window
    assert reg["gap_cv"] < irr["gap_cv"]
