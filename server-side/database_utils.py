import uuid
import os
from Crypto.Random import get_random_bytes

def compute_new_uuid():
    """
       Generates a new UUID (Universally Unique Identifier).

       Returns:
           UUID: A randomly generated UUID.
    """
    return uuid.uuid4()


def make_directory(directory_name):
    """
       Creates a new directory with the specified name.

       Args:
           directory_name (str): The name of the directory to create.

       If the directory already exists, no action is taken. If there is an error
       creating the directory, an error message is printed.
    """
    try:  # Was able to create users directory
        os.makedirs(directory_name)
    except OSError as error:  # Error couldn't create directory
        print(error)

