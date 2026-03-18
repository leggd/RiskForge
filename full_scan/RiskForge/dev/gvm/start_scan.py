# gvm_start_scan_and_get_report_id_beginner.py
# Creates a new target + task, starts it, polls progress, and grabs report_id ASAP.

from datetime import datetime
from time import sleep

from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

# -----------------------------
# CHANGE THESE
# -----------------------------
HOST = "10.0.96.32"
PORT = 9390
USERNAME = "admin"
PASSWORD = "378d6918-4340-4cfe-95f7-3f084d826d5d"

TARGET_HOST = "10.0.96.33"  # metasploitable / test host

SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"  # Full and fast
PORT_LIST_ID   = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"  # All IANA assigned TCP
SCANNER_ID     = "08b69003-5fc2-4037-a479-93b440211c73"  # OpenVAS Default
# -----------------------------

connection = TLSConnection(hostname=HOST, port=PORT)
transform = EtreeCheckCommandTransform()

with GMP(connection=connection, transform=transform) as gmp:
    gmp.authenticate(USERNAME, PASSWORD)
    print("Authenticated OK")

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # 1) Create a target
    target_name = "RiskForge Target " + TARGET_HOST + " " + now
    target_resp = gmp.create_target(
        name=target_name,
        hosts=[TARGET_HOST],
        port_list_id=PORT_LIST_ID
    )
    target_id = target_resp.get("id")
    print("Created target:", target_id)

    # 2) Create a task
    task_name = "RiskForge Task " + TARGET_HOST + " " + now
    task_resp = gmp.create_task(
        name=task_name,
        config_id=SCAN_CONFIG_ID,
        target_id=target_id,
        scanner_id=SCANNER_ID
    )
    task_id = task_resp.get("id")
    print("Created task:", task_id)

    # 3) Start the task
    gmp.start_task(task_id)
    print("Task start requested.")

    report_id = None

    # 4) Poll until finished (and grab report_id as soon as it appears)
    while True:
        # Get tasks list and locate THIS task by id
        tasks_xml = gmp.get_tasks(filter_string="rows=500")
        t = tasks_xml.find(".//task[@id='" + task_id + "']")

        if t is None:
            print("Task not found in list yet... waiting")
            sleep(3)
            continue

        status = (t.findtext("./status") or "").strip()
        progress = (t.findtext("./progress") or "").strip()

        # Grab report_id if available
        if report_id is None:
            current_report = t.find("./current_report/report")
            if current_report is not None:
                report_id = current_report.get("id")
                print("Report ID obtained:", report_id)

        print("Status:", status, "| Progress:", progress, "| Report ID:", report_id)

        if status in ("Done", "Stopped", "Interrupted", "Aborted", "Failed"):
            break

        sleep(10)

    print("\nFINAL STATUS:", status)
    print("TASK ID:", task_id)
    print("REPORT ID:", report_id)