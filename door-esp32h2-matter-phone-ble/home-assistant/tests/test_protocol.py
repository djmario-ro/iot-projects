import importlib.util
from pathlib import Path
import unittest
import hashlib
spec = importlib.util.spec_from_file_location("protocol", Path(__file__).parents[1]/"custom_components/doorkey/protocol.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
KEY = bytes.fromhex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")

class ProtocolTests(unittest.TestCase):
    def test_maximum_configuration_fits_stock_user_label(self):
        for name in ("A", "Door-204", "x"*29):
            labels=p.encode(name,KEY)
            self.assertEqual(len(labels),4)
            self.assertTrue(all(len(i['label'])<=16 and len(i['value'])<=16 for i in labels))
            self.assertEqual(p.decode(labels),(name,KEY))
            self.assertEqual(p.decode([{'0':i['label'],'1':i['value']} for i in reversed(labels)]),(name,KEY))
    def test_reject_incomplete_duplicate_and_unrelated_labels(self):
        labels=p.encode('Door-12',KEY)
        for bad in (labels[:-1],labels[:3]+[labels[0]],[{'label':'room','value':'204'}]):
            with self.assertRaises(ValueError):p.decode(bad)
    def test_pinned_key_rejects_substitution_and_invalid_points(self):
        digest=hashlib.sha256(KEY).hexdigest()
        self.assertEqual(p.checked_key(KEY.hex(),digest),KEY)
        with self.assertRaises(ValueError):p.checked_key(KEY.hex(),'0'*64)
        with self.assertRaises(ValueError):p.checked_key(('04'+'00'*64),digest)
    def test_write_status_distinguishes_refusal_from_missing_ack(self):
        p.check_write_result([{'Status':0}])
        p.check_write_result([{'status':0}])
        with self.assertRaisesRegex(ValueError, 'status=1'):p.check_write_result([{'Status':1}])
        with self.assertRaisesRegex(ValueError, 'no write status'):p.check_write_result(None)
    def test_names_and_keys_are_bounded(self):
        for name in ('','x'*30,'Door\n12','Ușă'):
            with self.assertRaises(ValueError):p.encode(name,KEY)
        with self.assertRaises(ValueError):p.encode('Door-12',bytes(65))

if __name__ == '__main__':unittest.main()
