from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform
from datetime import datetime

def start_gvm_scan(target_ip):
    """
    Starts a GVM scan for a single IP.
    Returns: task_id, report_id (may be None)
    """

    HOST = "10.0.96.32"
    PORT = 9390
    USERNAME = "admin"
    PASSWORD = "378d6918-4340-4cfe-95f7-3f084d826d5d"

    SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
    PORT_LIST_ID   = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
    SCANNER_ID     = "08b69003-5fc2-4037-a479-93b440211c73"

    connection = TLSConnection(hostname=HOST, port=PORT)
    transform = EtreeCheckCommandTransform()

    with GMP(connection=connection, transform=transform) as gmp:
        gmp.authenticate(USERNAME, PASSWORD)

        now = str(datetime.utcnow())
        # Create target
        target_resp = gmp.create_target(
            name="RiskForge Target " + target_ip + " " + now,
            hosts=[target_ip],
            port_list_id=PORT_LIST_ID
        )
        target_id = target_resp.get("id")

        # Create task
        task_resp = gmp.create_task(
            name="RiskForge Task " + target_ip + " " + now,
            config_id=SCAN_CONFIG_ID,
            target_id=target_id,
            scanner_id=SCANNER_ID
        )
        task_id = task_resp.get("id")

        # Start task
        gmp.start_task(task_id)

        # Immediately try to get report ID
        report_id = None

        tasks_xml = gmp.get_tasks(filter_string="rows=500")
        t = tasks_xml.find(".//task[@id='" + task_id + "']")
        if t is not None:
            current_report = t.find("./current_report/report")
            if current_report is not None:
                report_id = current_report.get("id")

        return task_id, report_id
    
def get_gvm_task_status(task_id):
    """
    Gets status and progress from GVM for a given task_id.
    Returns: status_string, progress_int
    """

    HOST = "10.0.96.32"
    PORT = 9390
    USERNAME = "admin"
    PASSWORD = "378d6918-4340-4cfe-95f7-3f084d826d5d"

    connection = TLSConnection(hostname=HOST, port=PORT)
    transform = EtreeCheckCommandTransform()

    with GMP(connection=connection, transform=transform) as gmp:
        gmp.authenticate(USERNAME, PASSWORD)

        tasks_xml = gmp.get_tasks(filter_string="rows=500")
        t = tasks_xml.find(".//task[@id='" + task_id + "']")

        if t is None:
            return "Unknown", 0

        status = (t.findtext("./status") or "").strip()
        progress = (t.findtext("./progress") or "0").strip()

        try:
            progress = int(progress)
        except:
            progress = 0

        return status, progress

