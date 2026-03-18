# report_id_from_task.py
# Poll a single task and print the report_id once it exists.
# Uses current_report first (during scan), then last_report fallback.

from time import sleep
from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

HOST = "10.0.96.32"
PORT = 9390
USERNAME = "admin"
PASSWORD = "378d6918-4340-4cfe-95f7-3f084d826d5d"

TASK_ID = "7fc60dda-29d5-490b-b517-1625b1ab8d09"   # <-- paste your task ID

connection = TLSConnection(hostname=HOST, port=PORT)
transform = EtreeCheckCommandTransform()

with GMP(connection=connection, transform=transform) as gmp:
    gmp.authenticate(USERNAME, PASSWORD)
    print("Authenticated OK")

    report_id = None

    while report_id is None:
        tasks_xml = gmp.get_tasks(filter_string="rows=500")
        t = tasks_xml.find(".//task[@id='" + TASK_ID + "']")

        if t is None:
            print("Task not found yet... waiting")
            sleep(5)
            continue

        status = (t.findtext("./status") or "").strip()
        progress = (t.findtext("./progress") or "").strip()

        # During scan: current_report
        current_report = t.find("./current_report/report")
        if current_report is not None:
            report_id = current_report.get("id")

        # If not present, try last_report
        if report_id is None:
            last_report = t.find("./last_report/report")
            if last_report is not None:
                report_id = last_report.get("id")

        print("Status:", status, "| Progress:", progress, "| Report ID:", report_id)
        sleep(5)

    print("\nFOUND REPORT ID:", report_id)