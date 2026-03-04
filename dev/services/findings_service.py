def store_findings(scan_id, asset_id, findings):
    from app import get_db_connection
    """
    Stores parsed scan findings in the findings table.

    Parameters:
        scan_id (int): ID of the scan the findings belong to
        asset_id (int): ID of the scanned asset
        findings (list): List of dictionaries returned by get_top_gvm_findings()
    """

    conn = get_db_connection()
    cur = conn.cursor()

    # Remove any existing findings for this scan (avoids duplicates)
    cur.execute("DELETE FROM findings WHERE scan_id = %s", (scan_id,))

    for f in findings:

        port = f.get("port")
        cvss_score = f.get("cvss_score")
        nvt_name = f.get("nvt_name")
        solution = f.get("solution")

        # Convert CVE list to comma separated string
        cves = ", ".join(f.get("cves", []))

        sql = """
        INSERT INTO findings
        (scan_id, asset_id, nvt_name, port, cvss_score, cves, solution)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        cur.execute(sql, (
            scan_id,
            asset_id,
            nvt_name,
            port,
            cvss_score,
            cves,
            solution
        ))

    conn.commit()

    cur.close()
    conn.close()