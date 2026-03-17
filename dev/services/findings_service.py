def store_findings(scan_id, asset_id, findings, created_by, min_score=5.0):
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

    cur.execute("SELECT criticality, exposure FROM assets WHERE asset_id = %s",(asset_id,))
    
    asset = cur.fetchone()

    if asset:
        criticality = asset["criticality"]
    else:
        criticality = "MEDIUM"

    if asset:
        exposure = asset["exposure"]
    else:
        exposure = "PUBLIC"

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

        riskforge_score = riskforge_score_calc(float(cvss_score),criticality,exposure)

        if riskforge_score == None:
            riskforge_score = 0
        

        # Store the finding row
        sql = """
        INSERT INTO findings
        (scan_id, asset_id, nvt_name, port, cvss_score, cves, solution, riskforge_score)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
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
                riskforge_score
            ),
        )

        # Auto-create ticket if CVSS meets threshold
        if float(riskforge_score) >= float(min_score):

            # Simple priority mapping for PoC
            if riskforge_score >= 15:
                priority = "Critical"
            elif riskforge_score >= 10:
                priority = "High"
            elif riskforge_score >= 5:
                priority = "Medium"
            else:
                priority = "Low"

            #if riskforge_score > float(10):
                #riskforge_score = float(10)

            title = nvt_name

            description = (
                f"Source: GVM Scan #{scan_id}\n"
                f"Asset ID: {asset_id}\n"
                f"Port: {port or '-'}\n"
                f"CVSS: {cvss_score}\n"
                f"RiskForge Score: {riskforge_score}\n"
                f"CVEs: {cves if cves else 'None'}\n\n"
                f"Solution:\n{solution if solution else 'No solution provided.'}"
            )

            ticket_sql = """
            INSERT INTO tickets
            (asset_id, scan_id, created_by, title, priority, status, description, riskforge_score)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
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
                    riskforge_score,
                ),
            )

    conn.commit()

    cur.close()
    conn.close()

def riskforge_score_calc (CVSS_score, CRITICALITY, EXPOSURE):
#declaring the values for the cruciality and exposure
    CRITICALITY_VALUES = {
    "LOW": 0.5,
    "MEDIUM": 1,
    "HIGH": 1.5,
    "MISSION_CRITICAL": 2 }

    EXPOSURE_VALUES = {
            "PRIVATE":0.75,
            "PUBLIC": 1
            }

    #error handling 
    if not isinstance(CVSS_score, (int, float)):
        print ("invalid CVSS score")
        return None

    if CRITICALITY not in CRITICALITY_VALUES:
        print ("invalid criticality value")
        return None

    elif EXPOSURE not in EXPOSURE_VALUES:
        print ("invalid exposure value")  
        return None 

    else: #calculates the risk score and returs the value 
            #assigning the values to the variables
        try:
            Criticality_value = CRITICALITY_VALUES.get(CRITICALITY)
            exposure_value = EXPOSURE_VALUES.get(EXPOSURE)

            Risk_Forge_score = CVSS_score * Criticality_value * exposure_value
            return Risk_Forge_score
        except Exception as e:
            print("Calculation error: " + str(e))
            return None
        
        