from cryptography.fernet import Fernet

def generate_key():
    """
    Generates a key and save it into a file
    """
    key = Fernet.generate_key()
    with open("./data/secret.key", "wb") as key_file:
        key_file.write(key)

generate_key()