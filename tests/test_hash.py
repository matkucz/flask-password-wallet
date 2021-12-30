import pytest
from project.hash import calculate_hmac, calculate_md5, calculate_sha512, verify_hashed_text

@pytest.mark.parametrize(
    ('text', 'hash'),
    (
        ('test', '098f6bcd4621d373cade4e832627b4f6'),
        ('kocham_bsi', '5e707c12772901db21cbe2d03944c17d'),
))
def test_calculate_md5_correct(text, hash):
    assert calculate_md5(text) == hash


@pytest.mark.parametrize(
    ('text', 'hash'),
    (
        ('test', '312fa3f245657a46662c8d65bb55e6db'),
        (' ', '5e707c12772901db21cbe2d03944c17d'),
))
def test_calculate_md5_invalid(text, hash):
    assert not calculate_md5(text) == hash


@pytest.mark.parametrize(
    ('text', 'hash'),
    (
        ('test', 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff'),
        ('kuczyński', '1880b756ac81a56fef6b6bbcc513cb0584b97ad4ac8d54ba6d40942d3edb0470819d9cc4494f94059496c09ad8540f1af1c041176d60cf4c006035dd0997502a'),
))
def test_calculate_sha512_correct(text, hash):
    assert calculate_sha512(text) == hash


@pytest.mark.parametrize(
    ('text', 'hash'),
    (
        ('test', 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f52028a8ff'),
        ('kuczyński', '1880b756ac81a56fef6b6bbcc513cb0584b97ad4ac8d54ba6d40942d3edb0470819d9cc4494f94059496c09ad8540f1af1c041176d60cf4e006035dd0997502a'),
))
def test_calculate_sha512_invalid(text, hash):
    assert not calculate_sha512(text) == hash


@pytest.mark.parametrize(
    ('text', 'salt', 'hash'),
    (
        ('test', 'kXVfcntIqsVIeInd', 'bd10ac5511269abc94ee7caaf29697a00f231caf09218b1240f7c5919dbc07f759088fa8eda71bd587d290389caaf22a12c7467f45e040628c4b2247665dc03f'),
        ('bardzo_krótki_tekst', 'mmnxDhzs8e9f1Fgk', '2d50a2c0157d8d275c4bc08ef89fae2b5b9a7fd570ac4c4dba5fa055e35df0cd2af6cba31332f3287277d119d22934ba88b11e08ed4672526132c61cea4e38d9'),
))
def test_calculate_hmac_correct(text, salt, hash):
    assert calculate_hmac(text, salt) == hash


@pytest.mark.parametrize(
    ('text', 'salt', 'hash'),
    (
        ('test', ' ', 'bd10ac5511269abc94ee7caaf29697a00f231caf09218b1240f7c5919dbc07f759088fa8eda71bd587d290389caaf22a12c7467f45e040628c4b2247665dc03f'),
        ('bardzo_krótki_tekst', 'nieznaczacytekst', '2d50a2c0157d8d275c4bc08ef89fae2b5b9a7fd570ac4c4dba5fa055e35df0cd2af6cba31332f3287277d119d22934ba88b11e08ed4672526132c61cea4e38d9'),
))
def test_calculate_hmac_invalid(text, salt, hash):
    assert not calculate_hmac(text, salt) == hash
