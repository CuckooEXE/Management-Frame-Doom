"""
Implements the Golay encoding for error-detection and error-correction

Author: Axel Persinger
License: MIT License
"""


"""
Imported Libraries

"""


def encode(msg: str) -> bytes:
    """
    Performs Golay message encoding

    :param msg: Message to send
    :type msg: str
    :return: Encoded bytes
    :rtype: bytes
    """
    # TODO: Implement this
    return msg


def decode(msg: bytes) -> list:
    """
    Performs Golay message decoding

    :param msg: Message portion of packet that's been carved out
    :type msg: bytes
    :return: List of tuples in form of [(orig_msg, decoded_msg, errors), ...]
    :rtype: bytes
    """
    # TODO: Implement this
    return msg


def xor(msg: bytes, key: bytes, strict: bool = False) -> bytes:
    """
    XOR encrypts/decrypts a message

    :param msg: Message to encrypt/decrypt
    :type msg: bytes
    :param key: Key to use
    :type key: bytes
    :param strict: If encrypting and this is set to True, the key MUST be at least as long as the message to enforce OTP rules, defaults to False
    :type strict: bool, optional
    :return: Encrypted/Decrypted message
    :rtype: bytes
    """
    if len(msg) > len(key) and strict:
        raise ValueError("Key must be at least as long as the Message when Strict is set to True")
    elif len(msg) > len(key): # Extend the key be the length of the message
        key = (key * (int(len(msg)/len(key))+1))[:len(msg)]

    return bytearray([c1 ^ c2 for c1, c2 in zip(msg, key)])

