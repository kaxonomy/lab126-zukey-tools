"""SYNTHETIC TEST DATA — NOT FROM A REAL DEVICE."""


def make_fake_serial() -> str:
    return "EXAMPLE123456789"


def make_fake_modhex_public_id() -> str:
    return "c" * 12


def make_fake_otp() -> str:
    return make_fake_modhex_public_id() + "b" * 32
