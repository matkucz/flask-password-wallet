import pytest
from project.cipher import decrypt


@pytest.mark.parametrize(
    ('text', 'key', 'encrypted'),
    (
        ('test', b'73eeac3fa1a0ce48f381ca1e6d71f077', 'WCZh+vtlsR8R/uMkq0wWow== 0fmWFY7F7SSrt5/jxRZE+Q=='),
        ('long_long_long_text', b'01fad983464dcf15ba5dbe153514e35f', '9CRwkV1eMJ0H+z3veJBtkGcJbxPOwn/9JsL2N6GOLKY= DArCNyEamFY9wo+PEKTDpA=='),
))
def test_decrypt_correct(text, key, encrypted):
    assert decrypt(encrypted, key).decode("utf-8") == text
