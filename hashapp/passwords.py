
import bcrypt


def password_hash(input_password):
    salt = bcrypt.gensalt(rounds=12)
    hashed_password = bcrypt.hashpw(input_password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')