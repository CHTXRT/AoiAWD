def rand_hex(len: int = 16) -> str:
    r"""Generate a random 16-character hexadecimal string.

    :return: A random 16-character hexadecimal string.
    :rtype: str
    """
    import random
    return ''.join(random.choices("0123456789abcdef", k=len*2))