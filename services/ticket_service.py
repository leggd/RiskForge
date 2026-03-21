from db import execute_query

def create_tickets(
    scan_id, asset_id, findings, created_by, min_score=4.0
):
    """
    Creates tickets from findings based on RiskForge score.
    """

    for f in findings:

        riskforge_score = f.get("riskforge_score", 0)

        if float(riskforge_score) < float(min_score):
            continue

        # determine priority
        if riskforge_score >= 9:
            priority = "Critical"
        elif riskforge_score >= 7:
            priority = "High"
        elif riskforge_score >= 4:
            priority = "Medium"
        else:
            priority = "Low"

        port = f.get("port")
        cvss_score = f.get("cvss_score") or 0
        nvt_name = f.get("nvt_name") or "Unnamed finding"
        solution = f.get("solution") or ""

        cves_list = f.get("cves", [])
        cves = ", ".join(cves_list)

        title = nvt_name

        description = (
            f"Source: Scan #{scan_id}\n"
            f"Asset ID: {asset_id}\n"
            f"Port: {port or '-'}\n"
            f"CVSS: {cvss_score}\n"
            f"RiskForge Score: {riskforge_score}\n"
            f"CVEs: {cves if cves else 'None'}\n\n"
            f"Solution:\n{solution if solution else 'No solution provided.'}"
        )

        sql = """
        INSERT INTO tickets (
        asset_id,
        scan_id,
        created_by,
        title,
        priority,
        status,
        description,
        riskforge_score)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """

        execute_query(
            sql,
            (
                asset_id,
                scan_id,
                created_by,
                title,
                priority,
                "Open",
                description,
                riskforge_score,
            ),
        )