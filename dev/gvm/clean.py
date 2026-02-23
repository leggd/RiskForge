# gvm_cleanup_riskforge.py
# Stops and deletes RiskForge tasks, deletes related reports, and (optionally) targets.

from time import sleep
from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

HOST = "10.0.96.32"
PORT = 9390
USERNAME = "admin"
PASSWORD = "378d6918-4340-4cfe-95f7-3f084d826d5d"

# Only delete objects whose names start with these prefixes
TASK_PREFIX = ""
TARGET_PREFIX = ""

# Set to True if you also want to delete RiskForge targets
DELETE_TARGETS = True

connection = TLSConnection(hostname=HOST, port=PORT)
transform = EtreeCheckCommandTransform()

with GMP(connection=connection, transform=transform) as gmp:
    gmp.authenticate(USERNAME, PASSWORD)
    print("Authenticated OK")

    # -----------------------------
    # 1) Find RiskForge tasks
    # -----------------------------
    tasks_xml = gmp.get_tasks(filter_string="rows=1000")
    tasks = tasks_xml.xpath(".//task")

    riskforge_tasks = []
    for t in tasks:
        name = (t.findtext("./name") or "").strip()
        if name.startswith(TASK_PREFIX):
            riskforge_tasks.append(t)

    print("RiskForge tasks found:", len(riskforge_tasks))

    # -----------------------------
    # 2) Stop tasks (if running/queued/requested)
    # -----------------------------
    for t in riskforge_tasks:
        task_id = t.get("id")
        name = (t.findtext("./name") or "").strip()
        status = (t.findtext("./status") or "").strip()

        # "Running", "Queued", "Requested" etc can be stopped
        if status in ("Running", "Queued", "Requested"):
            print("Stopping task:", name, task_id, "status:", status)
            try:
                gmp.stop_task(task_id)
            except Exception as e:
                print("Stop failed:", e)

    # Give gvmd a moment to process stops
    sleep(3)

    # -----------------------------
    # 3) Collect report IDs referenced by tasks (last_report)
    # -----------------------------
    # Refresh tasks list so statuses/last_report are updated
    tasks_xml = gmp.get_tasks(filter_string="rows=1000")
    tasks = tasks_xml.xpath(".//task")

    report_ids = []
    task_ids_to_delete = []

    for t in tasks:
        name = (t.findtext("./name") or "").strip()
        if not name.startswith(TASK_PREFIX):
            continue

        task_id = t.get("id")
        task_ids_to_delete.append(task_id)

        last_report_node = t.find("./last_report/report")
        if last_report_node is not None:
            rid = last_report_node.get("id")
            if rid and rid not in report_ids:
                report_ids.append(rid)

    print("Unique last_report IDs collected:", len(report_ids))

    # -----------------------------
    # 4) Delete tasks (ultimate=True removes entirely, not just trash)
    # -----------------------------
    for task_id in task_ids_to_delete:
        print("Deleting task:", task_id)
        try:
            gmp.delete_task(task_id, ultimate=True)
        except Exception as e:
            print("Delete task failed:", e)

    # -----------------------------
    # 5) Delete reports
    # -----------------------------
    # Note: delete_report in GMP v22.x does not use ultimate; it deletes the report.
    for rid in report_ids:
        print("Deleting report:", rid)
        try:
            gmp.delete_report(rid)
        except Exception as e:
            print("Delete report failed:", e)

    # -----------------------------
    # 6) Optionally delete RiskForge targets
    # -----------------------------
    if DELETE_TARGETS:
        targets_xml = gmp.get_targets(filter_string="rows=1000")
        targets = targets_xml.xpath(".//target")

        riskforge_targets = []
        for tgt in targets:
            name = (tgt.findtext("./name") or "").strip()
            if name.startswith(TARGET_PREFIX):
                riskforge_targets.append(tgt)

        print("RiskForge targets found:", len(riskforge_targets))

        for tgt in riskforge_targets:
            target_id = tgt.get("id")
            name = (tgt.findtext("./name") or "").strip()
            print("Deleting target:", name, target_id)
            try:
                gmp.delete_target(target_id, ultimate=True)
            except Exception as e:
                print("Delete target failed:", e)

    print("\nCleanup finished.")