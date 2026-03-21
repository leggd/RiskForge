from db import execute_query
from services.scoring_service import riskforge_score_calc

def store_findings(scan_id, asset_id, findings):
    """
    Stores parsed scan findings in the findings table.
    Returns findings with riskforge_score added.
    """

    # Fetch asset criticality and exposure
    sql = """
    SELECT criticality, exposure
    FROM assets
    WHERE asset_id = %s
    """
    asset = execute_query(sql, (asset_id), "one")

    criticality = asset["criticality"] if asset else "MEDIUM"
    exposure = asset["exposure"] if asset else "PUBLIC"

    updated_findings = []

    for f in findings:

        port = f.get("port")
        cvss_score = f.get("cvss_score") or 0
        nvt_name = f.get("nvt_name") or "Unnamed finding"
        solution = f.get("solution") or ""

        cves_list = f.get("cves", [])
        cves = ", ".join(cves_list)

        riskforge_score = riskforge_score_calc(
            float(cvss_score), criticality, exposure
        )

        if riskforge_score is None:
            riskforge_score = 0

        # store in DB
        sql = """
        INSERT INTO findings(
        scan_id, 
        asset_id, 
        nvt_name, 
        port, 
        cvss_score, 
        cves, 
        solution, 
        riskforge_score)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """

        execute_query(
            sql,
            (
                scan_id,
                asset_id,
                nvt_name,
                port,
                cvss_score,
                cves,
                solution,
                riskforge_score,
            ),
        )
        
        f["riskforge_score"] = riskforge_score
        updated_findings.append(f)

    return updated_findings