import bcrypt


def hash_password(raw_password: str) -> bytes:
    return bcrypt.hashpw(raw_password.encode("utf-8"), bcrypt.gensalt())
