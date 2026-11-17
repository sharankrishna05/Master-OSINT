"""Risk Scoring Engine for IntelBase OSINT intelligence (0 - 100 Scale)."""
import datetime
from typing import List
from .models import CheckResult, BreachRecord, RiskAssessment

HIGH_VALUE_SITES = {"github", "twitter", "x", "discord", "linkedin", "google", "aws", "microsoft"}

def calculate_risk_score(
    check_results: List[CheckResult],
    breaches: List[BreachRecord]
) -> RiskAssessment:
    """Calculate an explainable Risk Score (0 - 100) based on breach records and account footprint."""
    breach_points = 0
    footprint_points = 0
    reasons = []

    # 1. Breach Severity Evaluation (Max 55 Points)
    password_compromised = False
    current_year = datetime.datetime.now().year

    if breaches:
        # Check if passwords were exposed
        for b in breaches:
            if b.has_passwords:
                password_compromised = True
                break

        if password_compromised:
            breach_points += 25
            reasons.append("Account credentials/passwords exposed in confirmed public data breaches (+25)")

        # Breach volume points (+5 per breach, capped at 20)
        volume_pts = min(len(breaches) * 5, 20)
        breach_points += volume_pts
        reasons.append(f"Linked to {len(breaches)} historical breach database(s) (+{volume_pts})")

        # Recency evaluation (+10 if breach within last 2 years)
        has_recent = False
        for b in breaches:
            try:
                b_year = int(b.breach_date.split("-")[0])
                if current_year - b_year <= 2:
                    has_recent = True
                    break
            except Exception:
                pass

        if has_recent:
            breach_points += 10
            reasons.append("Recent breach exposure detected within past 24 months (+10)")
    else:
        reasons.append("No historical password breach exposure confirmed (0 breach points)")

    # 2. Account Footprint Evaluation (Max 45 Points)
    registered_sites = [r for r in check_results if r.exists is True]
    registered_names = {r.site_name.lower() for r in registered_sites}

    # High-value developer / corporate / social targets
    high_val_matches = registered_names.intersection(HIGH_VALUE_SITES)
    if high_val_matches:
        high_val_pts = min(len(high_val_matches) * 12, 30)
        footprint_points += high_val_pts
        reasons.append(f"Registered on {len(high_val_matches)} high-value target platform(s) [{', '.join(sorted(high_val_matches))}] (+{high_val_pts})")

    # General footprint coverage
    other_matches = registered_names - HIGH_VALUE_SITES
    if other_matches:
        other_pts = min(len(other_matches) * 5, 15)
        footprint_points += other_pts
        reasons.append(f"Active accounts identified across {len(other_matches)} auxiliary web service(s) (+{other_pts})")

    total_score = min(max(breach_points + footprint_points, 0), 100)

    # Classify Risk Level
    if total_score >= 85:
        level = "CRITICAL"
    elif total_score >= 65:
        level = "HIGH"
    elif total_score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    reasoning_text = " | ".join(reasons)

    return RiskAssessment(
        score=total_score,
        level=level,
        reasoning=reasoning_text,
        breach_count=len(breaches),
        password_compromised=password_compromised,
        registered_sites_count=len(registered_sites)
    )
