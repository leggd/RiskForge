def riskforge_score_calc(CVSS_score, CRITICALITY, EXPOSURE):
    """
    Calculates the RiskForge risk score by adjusting the CVSS score
    based on the asset's criticality and exposure.
    """
    CRITICALITY_VALUES = {
        "LOW":              0.8,
        "MEDIUM":           1,
        "HIGH":             1.3,
        "MISSION_CRITICAL": 1.6
    }

    EXPOSURE_VALUES = {
        "PRIVATE": 0.9,
        "PUBLIC":  1.2
    }

    if not isinstance(CVSS_score, (int, float)):
        print("invalid CVSS score")
        return None

    if CRITICALITY not in CRITICALITY_VALUES:
        print("invalid criticality value")
        return None

    elif EXPOSURE not in EXPOSURE_VALUES:
        print("invalid exposure value")
        return None

    else:
        try:
            Criticality_value = CRITICALITY_VALUES.get(CRITICALITY)
            exposure_value = EXPOSURE_VALUES.get(EXPOSURE)

            Risk_Forge_score = CVSS_score * Criticality_value * exposure_value
            # Return capped score to 1 decimal place

            return round(min(Risk_Forge_score, 10), 1)
        except Exception as e:
            print("Calculation error: " + str(e))
            return None