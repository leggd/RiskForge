from db import execute_query
from services.scoring_service import riskforge_score_calc

def store_findings(scan_id, asset_id, findings):
    """
    Store parsed scan findings in the database and calculate RiskForge scores

    Retrieves asset context (criticality and exposure), calculates a
    riskforge_score for each finding, inserts records into the findings table
    and returns the findings with scores attached
    """

    # Fetch asset criticality and exposure to calculate score
    sql = """
    SELECT criticality, exposure
    FROM assets
    WHERE asset_id = %s
    """
    asset = execute_query(sql, (asset_id), "one")

    # Apply defaults if asset not found (shouldn't happen)
    if asset:
        criticality = asset["criticality"]
    else:
        criticality = "MEDIUM"
    if asset:
        exposure = asset["exposure"]
    else:
        exposure = "PUBLIC"

    # Store updated findings with calculated scores
    updated_findings = []

    # Iterate through parsed findings
    for finding in findings:

        # Extract relevant fields with safe defaults
        port = finding.get("port")
        cvss_score = finding.get("cvss_score")
        if cvss_score is None:
            cvss_score = 0
        nvt_name = finding.get("nvt_name")
        if nvt_name is None:
            nvt_name = "Unnamed finding"
        solution = finding.get("solution")
        if solution is None:
            solution = ''

        # Convert CVE list into string for storage
        cves_list = finding.get("cves")
        if cves_list is None:
            cves_list = []
        cves = ", ".join(cves_list)

        # Calculate RiskForge score using CVSS + asset context
        riskforge_score = riskforge_score_calc(
            float(cvss_score), criticality, exposure)

        # Fallback if scoring function returns None
        if riskforge_score is None:
            riskforge_score = 0

        # Insert finding into database
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
        
        # Attach calculated score to finding variable for further use
        finding["riskforge_score"] = riskforge_score
        updated_findings.append(finding)

    # Return parsed findings with RiskForge score included
    return updated_findings

def prioritise_findings(findings):
    """
    Select a balanced subset of findings for ticket creation PoC

    Findings are grouped by RiskForge score into critical, high and medium
    categories. Up to four findings are selected from each category then
    any remaining slots (up to 12 total) are filled with the next
    highest findings
    """

    # Initiate list variables for each severity level
    critical = []
    high = []
    medium = []

    # Categorise findings based on different riskforge_score thresholds
    for finding in findings:
        score = finding["riskforge_score"]

        if score >= 9:
            critical.append(finding)
        elif score >= 7:
            high.append(finding)
        elif score >= 4:
            medium.append(finding)

    # Store final selected findings for ticket creation
    selected = []

    # Select up to 4 findings from each priority tier
    selected.extend(critical[:4])
    selected.extend(high[:4])
    selected.extend(medium[:4])

    # Collect remaining findings not yet selected
    remaining = []
    for finding in findings:
        if finding not in selected:
            remaining.append(finding)

    # Fill remaining slots up to maximum total of 12
    for finding in remaining:
        if len(selected) >= 12:
            break
        selected.append(finding)
        
    # Return prioritised findings
    return selected