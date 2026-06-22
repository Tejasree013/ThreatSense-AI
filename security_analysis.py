def generate_security_explanation(
    harmful_words,
    suspicious_links,
    executable_references,
    risk_score
):
    """
    Generate AI-style security explanation
    """

    keyword_count = len(harmful_words)
    link_count = len(suspicious_links)
    exe_count = len(executable_references)

    # Risk Level
    if risk_score >= 60:
        risk_level = "HIGH RISK"
    elif risk_score >= 20:
        risk_level = "MEDIUM RISK"
    else:
        risk_level = "LOW RISK"

    # Confidence Score
    confidence = min(
        95,
        50
        + (keyword_count * 5)
        + (link_count * 15)
        + (exe_count * 10)
    )

    # Threat Message
    if exe_count > 0 and link_count > 0:
        threat = (
            "This document may be attempting to distribute malware "
            "or redirect users to malicious websites."
        )

    elif exe_count > 0:
        threat = (
            "This document contains executable file references "
            "which could be used to deliver malicious software."
        )

    elif link_count > 0:
        threat = (
            "This document contains suspicious URLs that may redirect "
            "users to unsafe websites."
        )

    elif keyword_count > 0:
        threat = (
            "This document contains potentially dangerous security-related "
            "keywords that require further review."
        )

    else:
        threat = (
            "No significant threats were detected in this document."
        )

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "confidence": confidence,
        "keyword_count": keyword_count,
        "link_count": link_count,
        "exe_count": exe_count,
        "threat": threat
    }