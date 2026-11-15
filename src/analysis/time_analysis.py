import pandas as pd


def analyze_time_patterns(df: pd.DataFrame) -> dict:
    """Analyze daily and weekly malicious URL reports."""

    empty_result = {
        "daily_reports": {},
        "weekly_reports": {}
    }

    if df.empty or "date_added" not in df.columns:
        return empty_result

    result = df.copy()

    result["date_added"] = pd.to_datetime(
        result["date_added"],
        errors="coerce",
        utc=True
    )

    result = result.dropna(subset=["date_added"])

    if result.empty:
        return empty_result

    daily = (
        result.groupby(result["date_added"].dt.date)
        .size()
        .sort_index()
    )

    weekly = (
        result.set_index("date_added")
        .resample("W")
        .size()
    )

    return {
        "daily_reports": {
            str(date): int(count)
            for date, count in daily.items()
        },
        "weekly_reports": {
            str(date.date()): int(count)
            for date, count in weekly.items()
        }
    }


def analyze_online_duration(snapshots: pd.DataFrame) -> dict:
    """
    Estimate observed online duration using status snapshots.

    Duration is based on observation intervals, not exact
    infection or removal timestamps.
    """

    if snapshots.empty:
        return {
            "urls_analyzed": 0,
            "average_online_hours": None,
            "durations": []
        }

    required = {
        "malicious_url_id",
        "url_status",
        "observed_at"
    }

    if not required.issubset(snapshots.columns):
        raise ValueError("Required snapshot columns are missing")

    data = snapshots.copy()

    data["observed_at"] = pd.to_datetime(
        data["observed_at"],
        errors="coerce",
        utc=True
    )

    data = data.dropna(subset=["observed_at"])

    data["url_status"] = (
        data["url_status"].astype(str).str.lower()
    )

    durations = []

    for url_id, group in data.groupby("malicious_url_id"):
        group = group.sort_values("observed_at")

        online_times = group.loc[
            group["url_status"] == "online",
            "observed_at"
        ]

        offline_times = group.loc[
            group["url_status"] == "offline",
            "observed_at"
        ]

        if online_times.empty or offline_times.empty:
            continue

        first_online = online_times.min()
        first_offline_after = offline_times[
            offline_times >= first_online
        ]

        if first_offline_after.empty:
            continue

        last_online = first_offline_after.min()

        hours = (
            last_online - first_online
        ).total_seconds() / 3600

        durations.append({
            "url_id": int(url_id),
            "observed_online_hours": round(hours, 2)
        })

    values = [
        item["observed_online_hours"]
        for item in durations
    ]

    return {
        "urls_analyzed": len(durations),
        "average_online_hours": (
            round(sum(values) / len(values), 2)
            if values else None
        ),
        "durations": durations
    }