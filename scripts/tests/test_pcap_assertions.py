import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

path = Path(__file__).resolve().parents[1] / "test/assert_pcap.py"
spec = importlib.util.spec_from_file_location("pcap_assertions", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(endian="<", linktype=1, name=b"xdp:PASS", payload=b"abcd"):
    def block(kind, body):
        size = len(body)+12
        return struct.pack(endian+"II", kind, size)+body+struct.pack(endian+"I", size)
    shb = block(0x0a0d0d0a, struct.pack(endian+"IHHq", 0x1a2b3c4d, 1, 0, -1))
    option = struct.pack(endian+"HH", 2, len(name))+name+b"\0"*((-len(name)) % 4)
    idb = block(1, struct.pack(endian+"HHI", linktype, 0, 65535)+option+b"\0"*4)
    epb = block(6, struct.pack(endian+"IIIII", 0, 0, 1, len(payload), len(payload))+payload+b"\0"*((-len(payload)) % 4))
    return shb+idb, epb


class PcapAssertions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "final.pcap"

    def test_valid_both_byte_orders(self):
        for endian in ("<", ">"):
            header, packet = fixture(endian)
            self.path.write_bytes(header+packet*2)
            self.assertEqual(module.check(self.path, count=2, caplen=4, interface="xdp:PASS"), 2)

    def test_missing_empty_header_only_truncated_and_damaged(self):
        with self.assertRaises(FileNotFoundError):
            module.check(self.path)
        header, packet = fixture()
        for contents in (b"", header, header+packet[:-1], header+packet[:-4]+b"\0"*4):
            self.path.write_bytes(contents)
            with self.assertRaises(ValueError):
                module.check(self.path)

    def test_count_caplen_action_and_linktype_are_required(self):
        header, packet = fixture()
        self.path.write_bytes(header+packet)
        for kwargs in ({"count": 2}, {"caplen": 3}, {"interface": "xdp:DROP"}, {"linktype": 101}):
            with self.assertRaises(ValueError):
                module.check(self.path, **kwargs)
