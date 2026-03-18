from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

HOST = "10.0.96.32"
PORT = 9390
USERNAME = "admin"
PASSWORD = "378d6918-4340-4cfe-95f7-3f084d826d5d"

def main():
    connection = TLSConnection(hostname=HOST, port=PORT)
    transform = EtreeCheckCommandTransform()

    with GMP(connection=connection, transform=transform) as gmp:
        gmp.authenticate(USERNAME, PASSWORD)

        tasks_xml = gmp.get_tasks(filter_string="rows=200 sort-reverse=modification_time")
        tasks = tasks_xml.xpath(".//task")

        print(f"Found {len(tasks)} task(s)\n")

        for t in tasks:
            task_id = t.get("id")
            name = (t.findtext("./name") or "").strip()
            status = (t.findtext("./status") or "").strip()
            progress = (t.findtext("./progress") or "").strip()

            # "last_report" is commonly present:
            last_report_id = t.find("./last_report/report")
            last_report_id = last_report_id.get("id") if last_report_id is not None else None

            print(f"task={task_id}  status={status:10}  prog={progress:>3}%  last_report={last_report_id}  name={name}")

if __name__ == "__main__":
    main()