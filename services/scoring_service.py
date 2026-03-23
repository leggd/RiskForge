def riskforge_score_calc(CVSS_score, CRITICALITY, EXPOSURE):
    """
    Calculate a RiskForge score based on CVSS, criticality and exposure

    Applies weighting factors to the base CVSS score depending on the
    asset criticality and exposure level and returns a capped score
    rounded to one decimal place
    """

    # Weighting values for asset criticality
    CRITICALITY_VALUES = {
        "LOW":              0.8,
        "MEDIUM":           1,
        "HIGH":             1.3,
        "MISSION_CRITICAL": 1.6
    }

    # Weighting values for asset exposure
    EXPOSURE_VALUES = {
        "PRIVATE": 0.9,
        "PUBLIC":  1.2
    }

    # Validate CVSS input type
    if not isinstance(CVSS_score, (int, float)):
        print("invalid CVSS score")
        return None

    # Validate criticality input
    if CRITICALITY not in CRITICALITY_VALUES:
        print("invalid criticality value")
        return None

    # Validate exposure input
    elif EXPOSURE not in EXPOSURE_VALUES:
        print("invalid exposure value")
        return None

    else:
        try:
            # Retrieve weighting values
            Criticality_value = CRITICALITY_VALUES.get(CRITICALITY)
            exposure_value = EXPOSURE_VALUES.get(EXPOSURE)

            # Calculate adjusted risk score
            Risk_Forge_score = CVSS_score * Criticality_value * exposure_value

            # Cap score at 10 and round to 1 decimal place
            return round(min(Risk_Forge_score, 10), 1)

        except Exception as e:
            # Handle calculation errors
            print("Calculation error: " + str(e))
            return None