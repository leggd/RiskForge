# gvm_status_dashboard.py
# Shows a high-level live view of what GVM is doing (tasks + progress + targets)

import time
from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

HOST = "10.0.96.32"
PORT = 9390
USERNAME = "admin"
PASSWORD = "378d6918-4340-4cfe-95f7-3f084d826d5d"

REFRESH_SECONDS = 5
SHOW_ONLY_RISKFORGE = False   # set True to only show tasks named "RiskForge ..."

connection = TLSConnection(hostname=HOST, port=PORT)
transform = EtreeCheckCommandTransform()

with GMP(connection=connection, transform=transform) as gmp:
    gmp.authenticate(USERNAME, PASSWORD)
    print("Authenticated OK\n")

    while True:
        # Clear screen (works on Windows + Linux terminals usually)
        print("\n" * 50)

        # Pull tasks (increase rows if you have lots)
        tasks_xml = gmp.get_tasks(filter_string="rows=200 sort-reverse=modification_time")
        tasks = tasks_xml.xpath(".//task")

        running = 0
        queued = 0
        requested = 0
        done = 0
        other = 0

        print("=== GVM TASK DASHBOARD ===")
        print("Server:", HOST, "Port:", PORT)
        print("Time:", time.strftime("%Y-%m-%d %H:%M:%S"))
        print("Tasks returned:", len(tasks))
        print("Refresh every", REFRESH_SECONDS, "seconds")
        print()

        for t in tasks:
            task_id = t.get("id")
            name = (t.findtext("./name") or "").strip()

            if SHOW_ONLY_RISKFORGE and not name.startswith("RiskForge"):
                continue

            status = (t.findtext("./status") or "").strip()
            progress = (t.findtext("./progress") or "").strip()

            # Last report id (often appears once scan actually begins)
            last_report_node = t.find("./last_report/report")
            last_report_id = last_report_node.get("id") if last_report_node is not None else None

            # Target hosts (often inside <target><hosts> ... )
            target_hosts = None
            target_node = t.find("./target")
            if target_node is not None:
                target_hosts = (target_node.findtext("./hosts") or "").strip()
                if target_hosts == "":
                    target_hosts = None

            # Count statuses (rough)
            if status == "Running":
                running += 1
            elif status == "Queued":
                queued += 1
            elif status == "Requested":
                requested += 1
            elif status == "Done":
                done += 1
            else:
                other += 1

            print("----------------------------------------------")
            print("Name:     ", name)
            print("Task ID:  ", task_id)
            print("Status:   ", status, "| Progress:", progress + "%")
            print("Target:   ", target_hosts)
            print("Report ID:", last_report_id)

        print("\n=== SUMMARY ===")
        print("Running :", running)
        print("Queued  :", queued)
        print("Requested:", requested)
        print("Done    :", done)
        print("Other   :", other)

        time.sleep(REFRESH_SECONDS)