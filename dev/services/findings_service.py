def store_findings(scan_id, asset_id, findings, created_by, min_cvss=5.0):
    """
    Stores parsed scan findings in the findings table and (optionally)
    creates tickets for findings above a CVSS threshold.

    Parameters:
        scan_id (int): ID of the scan the findings belong to
        asset_id (int): ID of the scanned asset
        findings (list): List of dictionaries returned by get_gvm_findings()
        created_by (int): user_id of the person creating tickets
        min_cvss (float): minimum CVSS score required to auto-create a ticket
    """

    # Lazy import to avoid circular import with app.py
    from app import get_db_connection

    conn = get_db_connection()
    cur = conn.cursor()

    # Remove any existing findings for this scan (avoids duplicates)
    cur.execute("DELETE FROM findings WHERE scan_id = %s", (scan_id,))

    # Optional for PoC/testing: remove tickets for this scan so reruns don't duplicate
    cur.execute("DELETE FROM tickets WHERE scan_id = %s", (scan_id,))

    for f in findings:

        port = f.get("port")
        cvss_score = f.get("cvss_score") or 0
        nvt_name = f.get("nvt_name") or "Unnamed finding"
        solution = f.get("solution") or ""

        # Convert CVE list to comma separated string
        cves_list = f.get("cves", [])
        cves = ", ".join(cves_list)

        # Store the finding row
        sql = """
        INSERT INTO findings
        (scan_id, asset_id, nvt_name, port, cvss_score, cves, solution)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cur.execute(
            sql,
            (
                scan_id,
                asset_id,
                nvt_name,
                port,
                cvss_score,
                cves,
                solution,
            ),
        )

        # Auto-create ticket if CVSS meets threshold
        if float(cvss_score) >= float(min_cvss):

            # Simple priority mapping for PoC
            if cvss_score >= 9:
                priority = "Critical"
            elif cvss_score >= 7:
                priority = "High"
            else:
                priority = "Medium"

            title = nvt_name

            description = (
                f"Source: GVM Scan #{scan_id}\n"
                f"Asset ID: {asset_id}\n"
                f"Port: {port or '-'}\n"
                f"CVSS: {cvss_score}\n"
                f"CVEs: {cves if cves else 'None'}\n\n"
                f"Solution:\n{solution if solution else 'No solution provided.'}"
            )

            ticket_sql = """
            INSERT INTO tickets
            (asset_id, scan_id, created_by, title, priority, status, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cur.execute(
                ticket_sql,
                (
                    asset_id,
                    scan_id,
                    created_by,
                    title,
                    priority,
                    "Open",
                    description,
                ),
            )

    conn.commit()

    cur.close()
    conn.close()