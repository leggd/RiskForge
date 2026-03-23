from db import execute_query

def create_tickets(
    scan_id, asset_id, findings, created_by, min_score=4.0):
    """
    Create tickets from prioritised findings

    Iterates through findings, filters by minimum RiskForge score,
    assigns a priority level, formats ticket details and inserts
    records into the tickets table
    """

    # Iterate through findings to generate tickets
    for f in findings:

        # Retrieve RiskForge score (default to 0 if missing)
        riskforge_score = f.get("riskforge_score", 0)

        # Skip findings below minimum score threshold
        if float(riskforge_score) < float(min_score):
            continue

        # Determine ticket priority based on score
        if riskforge_score >= 9:
            priority = "Critical"
        elif riskforge_score >= 7:
            priority = "High"
        elif riskforge_score >= 4:
            priority = "Medium"
        else:
            priority = "Low"

        # Extract relevant finding data with safe defaults
        port = f.get("port")
        cvss_score = f.get("cvss_score") or 0
        nvt_name = f.get("nvt_name") or "Unnamed finding"
        solution = f.get("solution") or ""

        # Convert CVE list to comma-separated string
        cves_list = f.get("cves", [])
        cves = ", ".join(cves_list)

        # Use finding name as ticket title
        title = nvt_name

        # Prevent duplicate tickets to prevent clutter from PoC
        sql = """
        SELECT ticket_id FROM tickets
        WHERE asset_id = %s
        AND title = %s
        AND status = 'Open'
        """
        existing = execute_query(sql, (asset_id, title), "one")

        if existing:
            continue

        # Build detailed ticket description for context and remediation
        description = (
            f"Source: Scan #{scan_id}\n"
            f"Asset ID: {asset_id}\n"
            f"Port: {port or '-'}\n"
            f"CVSS: {cvss_score}\n"
            f"RiskForge Score: {riskforge_score}\n"
            f"CVEs: {cves if cves else 'None'}\n\n"
            f"Solution:\n{solution if solution else 'No solution provided.'}"
        )

        # Insert ticket into database
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