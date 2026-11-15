def classify_risk(score: int) -> dict:
    """Classify URL risk based on its numeric score."""

    try:
        score = int(score)
    except (ValueError, TypeError):
        score = 0

    score = max(0, min(score, 100))

    if score < 30:
        level = "Low"
        description = "Few suspicious patterns detected."

    elif score < 60:
        level = "Medium"
        description = "Several suspicious patterns detected."

    else:
        level = "High"
        description = "Multiple suspicious patterns detected."

    return {
        "score": score,
        "level": level,
        "description": description
    }