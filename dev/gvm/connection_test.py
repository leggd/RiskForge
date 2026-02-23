from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform
from lxml import etree

HOST = "10.0.96.32"
PORT = 9390

USERNAME = "admin"
PASSWORD = "378d6918-4340-4cfe-95f7-3f084d826d5d"

connection = TLSConnection(hostname=HOST, port=PORT)
transform = EtreeCheckCommandTransform()

with GMP(connection=connection, transform=transform) as gmp:
    # sanity check the manager responds
    print(gmp.get_version())

    # login to gvmd
    gmp.authenticate(USERNAME, PASSWORD)
    print("Authenticated OK")

    # quick proof: list targets (may be empty)
    targets_xml = gmp.get_targets()
    print(etree.tostring(gmp.get_scan_configs(), pretty_print=True).decode())
    print(etree.tostring(gmp.get_port_lists(), pretty_print=True).decode())
    print(etree.tostring(gmp.get_scanners(), pretty_print=True).decode())