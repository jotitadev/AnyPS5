import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_pe_references import reference


class TargetTests(unittest.TestCase):
    def test_name_count_beyond_the_file_is_rejected_before_allocating(self):
        image = reference()
        struct.pack_into("<I", image, 512 + 24, 0x01000000)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target.dll"
            target.write_bytes(image)
            result = subprocess.run([str(PATCHER), "libc", str(target)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("export name table out of bounds", result.stderr)
            self.assertEqual(target.read_bytes(), image)


if __name__ == "__main__":
    PATCHER = Path(sys.argv.pop(1)).resolve()
    unittest.main()
