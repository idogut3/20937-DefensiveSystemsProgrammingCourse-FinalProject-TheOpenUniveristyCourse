import database_utils
from CryptoUtils import encrypt_aes_key_with_public_key, compute_new_aes_key
from User import User
from UserFile import UserFile


class UserDatabase:
    """
        A class to manage a database of users, including user registration, retrieval,
        and file data management.

        Attributes:
            users (dict): A dictionary mapping UUID bytes to User objects.
            users_folders_directory_name (str): The directory where user folders are stored.
        """
    def __init__(self, users_folders_directory_name="users"):
        """
                Initializes the UserDatabase instance.

                Args:
                    users_folders_directory_name (str): The name of the directory for user folders.
                """
        self.users = dict()
        database_utils.make_directory(users_folders_directory_name)
        self.users_folders_directory_name = users_folders_directory_name

    def add_new_user_to_database(self, username):
        """
                Adds a new user to the database with a unique UUID and AES key.

                Args:
                    username (str): The username of the new user.

                Returns:
                    bytes: The UUID bytes of the newly created user.
        """
        uuid = database_utils.compute_new_uuid()
        uuid_str = str(uuid)
        uuid_bytes = uuid.bytes
        while uuid_bytes in self.users.keys():  # ensuring that the uuid is unique to the user - normally the code in this line would go through the uuid list only once
            uuid = database_utils.compute_new_uuid()
            uuid_str = str(uuid)
            uuid_bytes = uuid.bytes
        user_directory_path = self.users_folders_directory_name + "\\" + uuid_str
        database_utils.make_directory(user_directory_path)
        user_aes_key = compute_new_aes_key()

        self.users[uuid_bytes] = User(uuid=uuid_bytes, name=username, aes_key=user_aes_key,
                                      directory_path=user_directory_path)
        return uuid_bytes

    def is_username_already_registered(self, username: str) -> bool:
        """
               Checks if a given username is already registered in the database.

               Args:
                   username (str): The username to check.

               Returns:
                   bool: True if the username is registered, False otherwise.
        """
        for user in self.users.values():
            if user.get_name() == username:
                return True
        return False

    def is_uuid_registered_in_database(self, uuid: bytes):
        """
               Checks if a given UUID is registered in the database.

               Args:
                   uuid (bytes): The UUID to check.

               Returns:
                   bool: True if the UUID is registered, False otherwise.
        """
        for user in self.users.values():
            if user.get_uuid() == uuid:
                return True
        return False

    def get_user_by_username(self, username):
        """
               Retrieves a user object by username.

               Args:
                   username (str): The username of the user to retrieve.

               Returns:
                   User: The User object corresponding to the username.

               Raises:
                   KeyError: If the username is not found in the database.
        """
        for user in self.users.values():
            if user.get_name() == username:
                return user
        raise KeyError("Error: username: " + username + " not found in database")

    def get_user_by_uuid(self, uuid) -> User:
        """
               Retrieves a user object by UUID.

               Args:
                   uuid (bytes): The UUID of the user to retrieve.

               Returns:
                   User: The User object corresponding to the UUID.

               Raises:
                   KeyError: If the UUID is not found in the database.
        """
        for user in self.users.values():
            if user.get_uuid() == uuid:
                return user
        raise KeyError("Error User not found by uuid in database")

    def does_uuid_already_exist(self, uuid) -> bool:
        """
                Checks if a given UUID already exists in the database.

                Args:
                    uuid (bytes): The UUID to check.

                Returns:
                    bool: True if the UUID exists, False otherwise.
        """
        for user in self.users.values():
            if user.get_uuid() == uuid:
                return True
        return False

    def set_new_user_public_key(self, username, public_key):
        """
               Sets a new public key for a user and generates a new AES key.

               Args:
                   username (str): The username of the user.
                   public_key: The new public key to set.

               Raises:
                   KeyError: If the user is not found in the database.
        """
        found_user = False
        for user in self.users.values():
            if user.get_name() == username:
                found_user = True
                user.set_public_key(public_key)
                aes_key = compute_new_aes_key()
                user.set_aes_key(aes_key)
        if not found_user:
            raise KeyError("Error in database: couldn't locate user to set new public key to")


    def get_aes_key_by_uuid(self, client_id):
        """
               Retrieves the AES key for a user identified by UUID.

               Args:
                   client_id (bytes): The UUID of the user.

               Returns:
                   bytes: The AES key associated with the user.
        """
        for user in self.users.values():
            if user.get_uuid() == client_id:
                return user.get_aes_key()


    def save_user_file_data(self, uuid:bytes, send_file_payload_dict):
        """
               Saves file data for a user identified by UUID.

               Args:
                   uuid (bytes): The UUID of the user.
                   send_file_payload_dict (dict): A dictionary containing file data.

               The dictionary should contain keys like "file_name", "total_packets",
               "content_size", and "packet_number" for managing file packets.
        """
        user = self.get_user_by_uuid(uuid)
        if user.file is None:
            file = UserFile(user.get_directory_path() + "\\" + send_file_payload_dict["file_name"])
            file.set_file_name(send_file_payload_dict["file_name"])
            file.set_total_packets(send_file_payload_dict["total_packets"])
            file.set_encrypted_content_size(send_file_payload_dict["content_size"])
            user.set_file(file)
        user_file = user.get_file()
        user_file.add_packet_data(packet_number=send_file_payload_dict["packet_number"],
                                  data=send_file_payload_dict["message_content"])
        user.set_file(user_file)


    def remove_user_if_registered(self, username, uuid):
        """
               Removes a user from the database if the username and UUID match.

               Args:
                   username (str): The username of the user.
                   uuid (bytes): The UUID of the user.
        """
        for user in self.users.values():
            if user.get_name() == username and user.get_uuid() == uuid:
                self.remove_user_by_uuid(uuid)


    def remove_user_by_uuid(self, uuid):
        """
               Removes a user from the database using their UUID.

               Args:
                   uuid (bytes): The UUID of the user to remove.
        """
        self.users.pop(uuid)
