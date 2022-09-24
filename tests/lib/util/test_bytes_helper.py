from lib.helpers.bytes_helper import clean_byte_string

LONG_BYTES = b"\x04f\xff\xa1\x04f\xff\xa1\x04f\xff\xba\x04f\xff\xba\x04f\xff\xba\x04f\xff\xba\x04f\xff\xba\x04f\xff\xba\x04f\xff\xba\x04f\xff\xba\x04f\x00\x0b\x04f\x00\xb3\x04f\x00)\x04f\x00]\x04f\xff\xb8\x04f\x00A\x04f\x00\xa0\x04f\x00\r\x04f\x00d\x04f\xff\xeb\x04f\x00\x9a\x04f\xff\xe9\x04f\x00u\x04f\x00G\x04f\x01u\x04f\x01>\x04f\x01t\x04f\x028\x04f\x02\x8c\x04f\x02'\x04f\x02|\x04f\x01\x15\x04f\x01C\x04f\x00G\x04f\x00\r\x04f\xff\xf4\x04f\x00\x00\x04f\x008\x04f\xff\xee\x04f\xff\x9e\x04f\xff\xee\x04f\xff\x93\x04f\xff\xee\x04f\xff\xd4\x04f\x00m\x04f\x00\xa1\x04f\x00,\x04f\x00=\x04f\x008\x04f\x008\x04f\x00"


class TestBytesHelper:
    def test_clean_byte_string(self):
        assert clean_byte_string(b'\xbbJS') == '\\xbbJS'
        cleaned_bytes = clean_byte_string(LONG_BYTES)
        assert cleaned_bytes[0:4] == '\\x04'
        assert "\\'" not in cleaned_bytes
