from checksum import memcrc


def calculate_checksum_value(file):
    return memcrc(file)


