#!/usr/bin/env python3
"""
scanner_0.8.py - RiskForge Combined Scanner
============================================
Engines: GVM/OpenVAS (optional) + nmap + nikto + nuclei +
         testssl + gobuster + sqlmap + enum4linux

AI Analysis:
  - GVM is skipped automatically if socket is unavailable
  - Each finding gets its own dedicated AI request
  - 20s cooldown between AI requests (Groq rate limit)
  - Executive summary as a final separate request
  - Results saved to 3 JSON files
"""

import sys, os, json, subprocess, threading, time, socket
from datetime import datetime
from dotenv import load_dotenv
import requests, nmap, urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()
# Suppress SSL warnings caused by university network proxy blocking certificate verification
# ── CONFIG ───────────────────────────────────────────────────────────────────
# Groq LLM model used for AI vulnerability analysis
GROQ_API_KEY = "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"
GROQ_MODEL   = "llama-3.1-8b-instant"

# Database
#DB_HOST = os.getenv("DB_HOST", "localhost")
#DB_PORT = int(os.getenv("DB_PORT", 3306))
#DB_NAME = os.getenv("DB_NAME", "riskforge")
#DB_USER = os.getenv("DB_USER", "riskforge_user")
#DB_PASS = os.getenv("DB_PASS", "")
# GVM Unix socket path — only available when GVM service is running
GVM_SOCKET     = "/run/gvmd/gvmd.sock"
GVM_USER       = "admin"
GVM_PASS       = "1543815b-114f-448a-81f0-b53939d5b513"
# GVM scan profile: "Full and fast" — scans all common ports with full NVT checks
SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
PORT_LIST_ID   = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
SCANNER_ID     = "08b69003-5fc2-4037-a479-93b440211c73"
# Default wordlist for directory brute-forcing — comes with Kali
GOBUSTER_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
AI_DELAY          = 20    # seconds between AI requests
AI_MAX_FINDINGS   = 30    # max findings analyzed individually by AI

# ── HELPERS ──────────────────────────────────────────────────────────────────

def log(tag, msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [{tag}] {msg}", flush=True)
# Wrapper to run any shell tool and capture output, with timeout protection
def run_cmd(tag, cmd, timeout=600):
    log(tag, f"Running: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        log(tag, "Done.")
        return res.stdout or res.stderr or "(no output)"
    except subprocess.TimeoutExpired:
        log(tag, f"TIMEOUT after {timeout}s")
        return f"[{tag}] Timed out after {timeout}s"
    except FileNotFoundError:
        log(tag, "ERROR: tool not installed")
        return f"[{tag}] Tool not installed"
    except Exception as e:
        log(tag, f"ERROR: {e}")
        return f"[{tag}] Error: {e}"
# Sends a single prompt to Groq API and returns the text response
def groq_post(system_msg, user_msg, temperature=0.15):
    """Single Groq API call. Returns text or None."""
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
            json={
                "model": GROQ_MODEL,
                "max_tokens": 1024,
                "temperature": temperature,
                "messages": [
                    {"role": "system", "content": system_msg},
                    {"role": "user",   "content": user_msg},
                ],
            },
            timeout=90,
            verify=False,
        )
        data = r.json()
        if "choices" not in data:
            log("AI", f"Bad response: {str(data)[:200]}")
            return None
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        log("AI", f"Request failed: {e}")
        return None

# ── GVM SCANNER  ────────────────────────────────────────────────────
# Check if GVM is running before trying to connect — avoids hanging on startup
def gvm_available():
    if not os.path.exists(GVM_SOCKET):
        log("GVM", f"Socket not found: {GVM_SOCKET} — GVM skipped.")
        return False
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(GVM_SOCKET)
        s.close()
        return True
    except Exception as e:
        log("GVM", f"Socket unreachable ({e}) — GVM skipped.")
        return False
# Convert numeric CVSS score to human-readable severity label
def sev_label(score):
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score > 0.0:  return "Low"
    return "Log"
# Main GVM scan function — creates target, launches task, polls until done, parses findings
def run_gvm_scan(target_ip, result_container):
    if not gvm_available():
        result_container["gvm"] = {"skipped": True, "findings": []}
        return
    try:
        from gvm.connections import UnixSocketConnection
        from gvm.protocols.gmp import GMP
        from gvm.transforms import EtreeCheckCommandTransform

        log("GVM", f"Connecting to GVM for target {target_ip}...")
        conn = UnixSocketConnection(path=GVM_SOCKET, timeout=600)
        with GMP(connection=conn, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(GVM_USER, GVM_PASS)
            log("GVM", "Authenticated OK")
            now = str(datetime.utcnow())

            tr = gmp.create_target(
                name=f"RF-{target_ip}-{now}",
                hosts=[target_ip],
                port_list_id=PORT_LIST_ID
            )
            tid = tr.get("id")
            log("GVM", f"Target: {tid}")

            tk = gmp.create_task(
                name=f"RF-Task-{target_ip}-{now}",
                config_id=SCAN_CONFIG_ID,
                target_id=tid,
                scanner_id=SCANNER_ID
            )
            task_id = tk.get("id")
            log("GVM", f"Task: {task_id}")
            gmp.start_task(task_id)
            log("GVM", "Scan started, polling...")
            
            report_id = None
            # Poll GVM every 15 seconds until scan status changes to Done or Failed
            while True:
                xml = gmp.get_tasks(filter_string="rows=500")
                t   = xml.find(f".//task[@id='{task_id}']")
                if t is None:
                    time.sleep(10)
                    continue
                status   = (t.findtext("./status")  or "").strip()
                progress = (t.findtext("./progress") or "0").strip()
                if report_id is None:
                    cr = t.find("./current_report/report")
                    if cr is not None:
                        report_id = cr.get("id")

                log("GVM", f"Status: {status} | Progress: {progress}%")
                if status in ("Done", "Stopped", "Interrupted", "Aborted", "Failed"):
                    if report_id is None:
                        lr = t.find("./last_report/report")
                        if lr is not None:
                            report_id = lr.get("id")
                    break
                time.sleep(15)

            log("GVM", f"Scan done. Report: {report_id}")
            if not report_id:
                result_container["gvm"] = {"error": "No report ID", "findings": []}
                return

            rep = gmp.get_report(report_id=report_id, details=True, filter_string="rows=1000")

        def sev_f(r):
            try:    return float(r.findtext("severity") or 0)
            except: return 0.0
            # Sort findings by severity descending so critical issues appear first

        results  = sorted(rep.findall(".//report/results/result"), key=sev_f, reverse=True)
        findings = []
        for r in results:
            sev = sev_f(r)
            if sev <= 0: continue
            nvt  = r.find("nvt")
            cves = []
            if nvt is not None:
                for ref in nvt.findall(".//refs/ref"):
                    if (ref.get("type") or "").lower() == "cve":
                        c = ref.get("id")
                        if c: cves.append(c.strip())
            findings.append({
                "nvt_name":   (nvt.findtext("name") or "Unknown").strip() if nvt is not None else "Unknown",
                "port":       (r.findtext("port") or "").strip() or None,
                "cvss_score": sev,
                "severity":   (r.findtext("threat") or "").strip() or sev_label(sev),
                "cves":       cves,
                "solution":   (nvt.findtext("solution") or "").strip() if nvt is not None else None,
            })

        log("GVM", f"Parsed {len(findings)} findings.")
        result_container["gvm"] = {"report_id": report_id, "findings": findings}

    except Exception as e:
        log("GVM", f"ERROR: {e}")
        result_container["gvm"] = {"error": str(e), "findings": []}

# ── LOCAL SCANNERS ────────────────────────────────────────────────────────────

def run_nmap(target_ip):
    log("NMAP", "Starting deep scan (-sV -sC --script vuln)...")
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments="-sV -sC --script vuln -T4")
    output, is_web, is_smb = "", False, False
    if target_ip in nm.all_hosts():
        for proto in nm[target_ip].all_protocols():
            for port in nm[target_ip][proto].keys():
                svc = nm[target_ip][proto][port]
                output += f"\n[PORT {port}] {svc['name']} {svc.get('version','')}\n"
                for sid, sout in svc.get("script", {}).items():
                    output += f"  > {sid}: {str(sout)[:400]}\n"
                if port in [80, 443, 8080, 8443] or svc["name"] in ["http","https"]:
                    is_web = True
                if port in [139, 445] or svc["name"] in ["netbios-ssn","microsoft-ds"]:
                    is_smb = True
    log("NMAP", f"Done. Web={is_web} SMB={is_smb}")
    return output, is_web, is_smb

def run_nikto(ip):
    return run_cmd("NIKTO",    ["nikto", "-h", ip, "-maxtime", "120s", "-nointeractive"], 150)

def run_nuclei(ip):
    return run_cmd("NUCLEI",   ["nuclei", "-u", ip, "-severity", "medium,high,critical", "-silent"], 180)

def run_testssl(ip):
    return run_cmd("TESTSSL",  ["testssl", "--color", "0", "--quiet", "--fast", ip], 180)

def run_gobuster(ip):
    if not os.path.exists(GOBUSTER_WORDLIST):
        return f"Gobuster: wordlist not found ({GOBUSTER_WORDLIST})"
    return run_cmd("GOBUSTER", [
        "gobuster","dir","-u",f"http://{ip}","-w",GOBUSTER_WORDLIST,
        "-q","-t","20","--timeout","5s","-o","/dev/null"
    ], 180)

def run_sqlmap(ip):
    return run_cmd("SQLMAP", [
        "sqlmap","-u",f"http://{ip}","--crawl=2","--batch",
        "--level=2","--risk=1","--timeout=10",
        "--output-dir=/tmp/sqlmap_rf","--forms","-q"
    ], 300)

def run_enum4linux(ip):
    return run_cmd("ENUM4LINUX", ["enum4linux","-a",ip], 120)

def run_local_scanners(target_ip, result_container):
    try:
        nmap_out, is_web, is_smb = run_nmap(target_ip)
        combined = f"--- NMAP ---\n{nmap_out}\n"

        if is_web:
            log("LOCAL", "Web ports found — running web scanners in parallel...")
            web = {}
            def _r(name, fn): web[name] = fn(target_ip)
            threads = [
                threading.Thread(target=_r, args=("nikto",    run_nikto)),
                threading.Thread(target=_r, args=("nuclei",   run_nuclei)),
                threading.Thread(target=_r, args=("testssl",  run_testssl)),
                threading.Thread(target=_r, args=("gobuster", run_gobuster)),
                threading.Thread(target=_r, args=("sqlmap",   run_sqlmap)),
            ]
            for t in threads: t.daemon = True; t.start()
            for t in threads: t.join()
            combined += "".join(f"--- {k.upper()} ---\n{v}\n" for k,v in web.items())
        else:
            log("LOCAL", "No web ports — web scanners skipped.")

        if is_smb:
            log("LOCAL", "SMB ports found — running enum4linux...")
            combined += f"--- ENUM4LINUX ---\n{run_enum4linux(target_ip)}\n"
        else:
            log("LOCAL", "No SMB ports — enum4linux skipped.")

        result_container["local"] = combined
    except Exception as e:
        log("LOCAL", f"ERROR: {e}")
        result_container["local"] = f"ERROR: {e}"

# ── AI: EXTRACT FINDINGS FROM LOCAL SCANNERS ─────────────────────────────────

def extract_findings_from_local(local_data, target_ip):
    """
    When GVM is unavailable, parse structured findings from raw
    nmap/nikto/nuclei/testssl output using AI.
    Sends data in chunks of 3000 chars to stay under token limits.
    """
    if not local_data or len(local_data.strip()) < 50:
        log("AI", "No local scanner data to extract from.")
        return []

    log("AI", "Extracting structured findings from local scanner output...")

    # Send only first 3000 chars — enough for nmap+nikto findings
    chunk = local_data[:3000]

    prompt = f"""You are parsing raw security scanner output for target {target_ip}.
Extract every vulnerability, misconfiguration, and security issue found.

SCANNER OUTPUT:
{chunk}

Return ONLY a JSON array like this (no text before or after, no markdown):
[
  {{
    "nvt_name": "vsFTPd 2.3.4 Backdoor Command Execution",
    "port": "21/tcp",
    "cvss_score": 10.0,
    "severity": "Critical",
    "cves": ["CVE-2011-2523"],
    "solution": "Update vsFTPd to version 3.x"
  }},
  {{
    "nvt_name": "OpenSSH Outdated Version",
    "port": "22/tcp",
    "cvss_score": 7.5,
    "severity": "High",
    "cves": ["CVE-2023-38408"],
    "solution": "Update OpenSSH to latest version"
  }}
]

Include every open port with a known vulnerability or security issue.
severity must be: Critical / High / Medium / Low
cves must be an array, use [] if no CVE known."""

    raw = groq_post(PENTEST_SYSTEM, prompt, temperature=0.1)
    if not raw:
        log("AI", "No response from Groq.")
        return []

    log("AI", f"Raw AI response: {raw[:400]}")

    # Extract JSON array from response — grab everything between [ and ]
    raw = raw.strip()
    start = raw.find("[")
    end   = raw.rfind("]")

    if start == -1 or end == -1 or end <= start:
        log("AI", f"No valid JSON array in response. Full response: {raw[:500]}")
        return []

    json_str = raw[start:end+1]

    try:
        findings = json.loads(json_str)
        if not isinstance(findings, list):
            log("AI", "Response is not a list.")
            return []
        log("AI", f"Successfully extracted {len(findings)} findings from local scanners.")
        return findings
    except json.JSONDecodeError as e:
        log("AI", f"JSON decode error: {e}")
        log("AI", f"Attempted to parse: {json_str[:400]}")
        return []


# ── AI: PER-FINDING ANALYSIS ─────────────────────────────────────────────────

PENTEST_SYSTEM = (
    "You are a Senior Penetration Tester with 15+ years experience in offensive security, "
    "CVE research, and red team engagements. Every statement must reference the actual finding. "
    "No generic advice. Think like an attacker, write like an analyst."
)

def analyze_finding(idx, finding, target_ip):
    """Send one AI request for a single vulnerability. Returns analysis dict."""
    cves = ", ".join(finding.get("cves", [])) or "none"
    fix  = (finding.get("solution") or "")[:300]

    prompt = f"""Analyze this vulnerability on target {target_ip}:

Name:      {finding.get('nvt_name','Unknown')}
Port:      {finding.get('port','unknown')}
CVSS:      {finding.get('cvss_score', 0)}
Severity:  {finding.get('severity','unknown')}
CVEs:      {cves}
Fix hint:  {fix}

Return ONLY valid JSON, no text outside:
{{
  "score": <1-10 integer>,
  "risk_level": "<Critical|High|Medium|Low|Info>",
  "impact": "<one sentence — what attacker can actually do>",
  "exploit_likelihood": "<High|Medium|Low>",
  "recommendation": "<concrete fix, include version numbers>",
  "priority": "<Immediate|Short-term|Long-term>"
}}

Score guide:
9-10 = RCE / full compromise / auth bypass
7-8  = Privilege escalation / data breach / lateral movement
5-6  = Exploitable under certain conditions
3-4  = Low risk, hard to exploit
1-2  = Informational only"""

    log("AI", f"  [{idx+1}/{AI_MAX_FINDINGS}] {finding.get('nvt_name','?')[:55]}...")
    raw = groq_post(PENTEST_SYSTEM, prompt, temperature=0.1)
    if not raw:
        return _cvss_fallback(finding)

    raw = raw.strip()
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1][4:] if len(parts) > 1 and parts[1].startswith("json") else (parts[1] if len(parts) > 1 else raw)
    raw = raw.strip()

    try:
        result = json.loads(raw)
        log("AI", f"  → Score: {result.get('score','?')}/10  Risk: {result.get('risk_level','?')}")
        return result
    except Exception:
        log("AI", "  → JSON parse failed — using CVSS fallback")
        return _cvss_fallback(finding)

def _cvss_fallback(finding):
    score = min(round(finding.get("cvss_score", 0)), 10)
    return {
        "score":              score,
        "risk_level":         finding.get("severity", "Unknown"),
        "impact":             "Score derived from CVSS (AI unavailable)",
        "exploit_likelihood": "Medium",
        "recommendation":     finding.get("solution") or "See vendor advisory.",
        "priority":           "Short-term",
    }

def analyze_all_findings(findings, target_ip):
    """Analyze each finding individually with AI_DELAY between requests."""
    if not findings:
        log("AI", "No findings — skipping AI analysis.")
        return findings

    total   = min(len(findings), AI_MAX_FINDINGS)
    skipped = len(findings) - total

    log("AI", f"Per-finding AI analysis: {total} findings, {AI_DELAY}s between each.")
    if skipped > 0:
        log("AI", f"  Remaining {skipped} findings will use CVSS fallback.")

    for i, f in enumerate(findings):
        if i < total:
            analysis = analyze_finding(i, f, target_ip)
        else:
            analysis = _cvss_fallback(f)

        f["ai_score"]    = analysis.get("score", 0)
        f["ai_analysis"] = analysis

        if i < total - 1:
            log("AI", f"  Cooling down {AI_DELAY}s...")
            time.sleep(AI_DELAY)

    log("AI", "Per-finding analysis complete.")
    return findings

# ── AI: EXECUTIVE SUMMARY ─────────────────────────────────────────────────────

def generate_summary(target_ip, findings, local_data):
    log("AI", f"Preparing executive summary (cooling down {AI_DELAY}s)...")
    time.sleep(AI_DELAY)

    critical = [f for f in findings if f.get("ai_score",0) >= 8]
    high     = [f for f in findings if 6 <= f.get("ai_score",0) <= 7]
    medium   = [f for f in findings if 4 <= f.get("ai_score",0) <= 5]
    low      = [f for f in findings if f.get("ai_score",0) <= 3]

    def fmt(lst, n=4):
        lines = ""
        for f in lst[:n]:
            a    = f.get("ai_analysis", {})
            cves = ", ".join(f.get("cves",[])) or "none"
            lines += (
                f"  [{f.get('ai_score','?')}/10] {f.get('nvt_name','?')} "
                f"(port {f.get('port','?')}) CVEs: {cves}\n"
                f"    Impact: {a.get('impact','')}\n"
                f"    Fix: {a.get('recommendation','')[:120]}\n"
            )
        return lines or "  None\n"

    summary_block = (
        f"CRITICAL ({len(critical)}):\n{fmt(critical)}"
        f"HIGH ({len(high)}):\n{fmt(high)}"
        f"MEDIUM ({len(medium)}):\n{fmt(medium)}"
        f"LOW ({len(low)}):\n{fmt(low)}"
    )

    prompt = f"""Penetration test complete on target: {target_ip}
Total findings: {len(findings)} — Critical: {len(critical)} | High: {len(high)} | Medium: {len(medium)} | Low: {len(low)}

TOP FINDINGS:
{summary_block}

LOCAL SCANNERS SNIPPET:
{(local_data or '')[:1500]}

Write a professional penetration test report:

## EXECUTIVE SUMMARY
Overall risk rating + 2-3 sentence justification based on actual findings.
Stats: total / critical / high / medium / low

## ATTACK CHAIN ANALYSIS
Can findings be chained for greater impact? Describe the realistic attack path step-by-step.

## REMEDIATION ROADMAP
- Immediate (24-48h):
- Short-term (1-2 weeks):
- Long-term (1 month):

## TECHNICAL HARDENING
Specific configs, firewall rules, exact CVEs and versions. No generic advice."""

    raw = groq_post(PENTEST_SYSTEM, prompt, temperature=0.2)
    if not raw:
        return "Executive summary unavailable — AI request failed."
    log("AI", "Executive summary received.")
    return raw

# ── SAVE ─────────────────────────────────────────────────────────────────────

def save_results(target_ip, gvm_data, local_data, findings, summary):
    ts, slug = datetime.now().strftime("%Y%m%d_%H%M%S"), target_ip.replace(".", "_")

    full  = f"scan_report_{slug}_{ts}.json"
    allf  = f"all_findings_{slug}_{ts}.json"
    critf = f"critical_findings_{slug}_{ts}.json"

    with open(full, "w", encoding="utf-8") as f:
        json.dump({
            "target": target_ip, "scanned_at": datetime.now().isoformat(),
            "gvm_report_id": gvm_data.get("report_id"),
            "gvm_skipped":   gvm_data.get("skipped", False),
            "total_findings": len(findings),
            "findings": findings, "local_scan_raw": local_data,
            "executive_summary": summary,
        }, f, indent=2, ensure_ascii=False)
    log("SAVE", f"Full report: {full}")

    with open(allf, "w", encoding="utf-8") as f:
        json.dump({"target": target_ip, "scanned_at": datetime.now().isoformat(),
                   "total": len(findings), "findings": findings},
                  f, indent=2, ensure_ascii=False)
    log("SAVE", f"All findings ({len(findings)}): {allf}")

    crit = [f for f in findings if f.get("ai_score", 0) > 5]
    with open(critf, "w", encoding="utf-8") as f:
        json.dump({"target": target_ip, "scanned_at": datetime.now().isoformat(),
                   "total": len(crit), "findings": crit},
                  f, indent=2, ensure_ascii=False)
    log("SAVE", f"Critical findings >5 ({len(crit)}): {critf}")

    # 4. Remediation plan
    plan = generate_remediation_plan(findings, target_ip)
    plan_path = f"remediation_plan_{slug}_{ts}.json"
    with open(plan_path, "w", encoding="utf-8") as f:
        json.dump({
            "target":     target_ip,
            "scanned_at": datetime.now().isoformat(),
            "plan":       plan
        }, f, indent=2, ensure_ascii=False)
    log("SAVE", f"Remediation plan: {plan_path}")

    return full, allf, critf, plan_path

def generate_remediation_plan(findings, target_ip):
    """Generate a remediation plan using AI. Returns a dict."""
    if not findings:
        return {}

    log("AI", f"Generating remediation plan ({AI_DELAY}s cooldown)...")
    time.sleep(AI_DELAY)

    lines_text = ""
    for f in findings[:8]:
        a    = f.get("ai_analysis", {})
        cves = ", ".join(f.get("cves", []) or ["none"])
        rec  = a.get("recommendation", "")[:80]
        lines_text += f"- [{f.get('ai_score','?')}/10] {f.get('nvt_name','?')} port={f.get('port','?')} CVEs={cves} fix={rec}\n"

    system = "You are a security engineer. Return ONLY valid compact JSON. No markdown. No text outside JSON."
    count = len(findings[:8])
    user   = (
        f"Target: {target_ip}\nFindings ({count} total — include ALL of them):\n{lines_text}\n"
        f"Create a remediation_steps array with exactly {count} entries, one per finding above.\n"
        "Return ONLY compact JSON:\n"
        '{"overall_risk":"Critical","estimated_fix_time":"4 hours",'
        '"quick_wins":["disable FTP port 21","update OpenSSH","patch Bind DNS"],'
        '"remediation_steps":[{"priority":"Immediate","vulnerability":"name","port":"21/tcp",'
        '"cves":["CVE-XXXX"],"fix":"apt remove vsftpd && apt install vsftpd=3.0.5","verify":"vsftpd --version"}]}'
    )

    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
            json={
                "model": GROQ_MODEL,
                "max_tokens": 2048,
                "temperature": 0.1,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user},
                ],
            },
            timeout=90,
            verify=False,
        )
        raw = r.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        log("AI", f"Request failed: {e}")
        return {"error": str(e)}

    log("AI", f"Remediation response (200 chars): {raw[:200]}")

    # Find JSON boundaries
    s = raw.find("{")
    e = raw.rfind("}")
    if s == -1 or e == -1:
        return {"error": "No JSON in response", "raw": raw[:300]}

    try:
        plan = json.loads(raw[s:e+1])
        log("AI", "Remediation plan parsed successfully.")
        return plan
    except json.JSONDecodeError as ex:
        log("AI", f"JSON parse error: {ex}")
        return {"error": str(ex), "raw": raw[:300]}


# ── DATABASE ─────────────────────────────────────────────────────────────────

def save_to_db(target_ip, findings, summary, gvm_report_id=None):
    """
    Save scan results to MySQL riskforge database.
    Creates asset if not exists, creates scan record, inserts all findings.
    Returns scan_id or None on failure.
    """
    try:
        import pymysql
    except ImportError:
        log("DB", "pymysql not installed — run: pip install pymysql")
        return None

    conn = None
    try:
        conn = pymysql.connect(
            host=DB_HOST, port=DB_PORT,
            user=DB_USER, password=DB_PASS,
            database=DB_NAME, charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor
        )
        log("DB", "Connected to database.")

        with conn.cursor() as cur:

            # ── 1. Get or create asset by IP ──────────────────────────────
            cur.execute(
                "SELECT asset_id FROM assets WHERE ip_address = %s LIMIT 1",
                (target_ip,)
            )
            row = cur.fetchone()

            if row:
                asset_id = row["asset_id"]
                log("DB", f"Asset found: id={asset_id}")
                # Update last_scanned_at
                cur.execute(
                    "UPDATE assets SET last_scanned_at = %s WHERE asset_id = %s",
                    (datetime.now(), asset_id)
                )
            else:
                cur.execute(
                    """INSERT INTO assets (name, ip_address, asset_type, exposure, criticality)
                       VALUES (%s, %s, %s, %s, %s)""",
                    (target_ip, target_ip, "server", "internal", "high")
                )
                asset_id = cur.lastrowid
                log("DB", f"Asset created: id={asset_id}")

            # ── 2. Create scan record ──────────────────────────────────────
            cur.execute(
                """INSERT INTO scans
                   (asset_id, started_by, gvm_report_id, status, engine,
                    ai_verdict, finished_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (
                    asset_id,
                    "scanner_0.8",
                    gvm_report_id,
                    "completed",
                    "FULL",
                    summary[:5000] if summary else None,
                    datetime.now(),
                )
            )
            scan_id = cur.lastrowid
            log("DB", f"Scan record created: scan_id={scan_id}")

            # ── 3. Insert findings ─────────────────────────────────────────
            inserted = 0
            for f in findings:
                cves_str = ", ".join(f.get("cves") or [])
                cur.execute(
                    """INSERT INTO findings
                       (scan_id, asset_id, nvt_name, port, cvss_score,
                        cves, solution, created_at)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        scan_id,
                        asset_id,
                        f.get("nvt_name", "Unknown")[:255],
                        f.get("port", "")[:50],
                        f.get("cvss_score", 0),
                        cves_str[:500],
                        (f.get("solution") or "")[:1000],
                        datetime.now(),
                    )
                )
                inserted += 1

            conn.commit()
            log("DB", f"Saved {inserted} findings to database. scan_id={scan_id}")
            return scan_id

    except Exception as e:
        log("DB", f"ERROR: {e}")
        if conn:
            conn.rollback()
        return None
    finally:
        if conn:
            conn.close()


# ── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scanner_0.8.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1].strip()
    print("=" * 64)
    print(f"  RISKFORGE SCANNER v0.8 — target: {target_ip}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  Engines: GVM (optional) + nmap + nikto + nuclei +")
    print("           testssl + gobuster + sqlmap + enum4linux")
    # Shared container passed to both threads so results can be collected after join
    print(f"  AI: per-finding requests ({AI_DELAY}s cooldown) + summary")
    print("=" * 64)

    container = {"gvm": None, "local": None}

    t_gvm   = threading.Thread(target=run_gvm_scan,       args=(target_ip, container), daemon=True)
    t_local = threading.Thread(target=run_local_scanners, args=(target_ip, container), daemon=True)
    t_gvm.start(); t_local.start()

    log("MAIN", "All scanners running in parallel...")
    t_local.join(); log("MAIN", "Local scanners complete.")
    t_gvm.join();   log("MAIN", "GVM complete.")
# Fall back to local scanner output if GVM was skipped or returned nothing
    gvm_data   = container.get("gvm") or {}
    local_data = container.get("local") or ""
    findings   = gvm_data.get("findings", [])

    if gvm_data.get("skipped") or len(findings) == 0:
        log("MAIN", "GVM unavailable — extracting findings from local scanner output...")
        log("MAIN", f"Waiting {AI_DELAY}s before AI extraction...")
        time.sleep(AI_DELAY)
        findings = extract_findings_from_local(local_data, target_ip)
        if len(findings) == 0:
            log("MAIN", "WARNING: No findings extracted. Check local scanner output above.")
    else:
        log("MAIN", f"Using {len(findings)} findings from GVM.")

    log("MAIN", f"AI phase starting — {len(findings)} findings to analyze.")
    findings = analyze_all_findings(findings, target_ip)
    summary  = generate_summary(target_ip, findings, local_data)

    print("\n" + "=" * 64)
    print("  EXECUTIVE SUMMARY")
    print("=" * 64)
    print(summary)
    # Persist results to MySQL so the web interface can display them

    print("=" * 64)

    full, allf, critf, plan_path = save_results(target_ip, gvm_data, local_data, findings, summary)
    
    output = {
    "findings": findings,
    "summary": summary
    }
    print("RISKFORGE_OUTPUT:" + json.dumps(output))
    
    # Save to database
    # scan_id = save_to_db(
    #     target_ip, findings, summary,
    #     gvm_report_id=gvm_data.get("report_id")
    # )

    # print("\n" + "=" * 64)
    # print("  SAVED FILES")
    # print("=" * 64)
    # print(f"  Full report:         {full}")
    # print(f"  All findings:        {allf}")
    # print(f"  Critical (>5/10):    {critf}")
    # print(f"  Remediation plan:    {plan_path}")
    # if scan_id:
    #     print(f"  Database:            scan_id={scan_id} ({len(findings)} findings)")
    # else:
    #     print(f"  Database:            FAILED (check DB connection)")
    # print("=" * 64)

if __name__ == "__main__":
    main()