from UserFile import UserFile


class User:
    def __init__(self, uuid:bytes, name, directory_path, aes_key, public_key=""):
        self.uuid = uuid
        self.name = name
        self.public_key = public_key
        self.aes_key = aes_key
        self.directory_path = directory_path
        self.file: UserFile | None = None

    def get_uuid(self):
        return self.uuid

    def get_name(self):
        return self.name

    def get_public_key(self):
        return self.public_key

    def set_public_key(self, public_key):
        self.public_key = public_key

    def set_aes_key(self, aes_key):
        self.aes_key = aes_key

    def get_aes_key(self):
        return self.aes_key

    def get_directory_path(self):
        return self.directory_path

    def set_file(self, file):
        self.file = file

    def get_file(self) -> UserFile:
        if self.file is None:
            raise Exception("Error, user doesnt have a user_file yet")
        return self.file

    def get_user_file_path(self, file_name):
        return self.directory_path + "\\" + file_name

    def received_entire_file(self) -> bool:
        if self.file is None:
            return False
        return self.file.received_entire_file()

    def add_packet_to_file_data(self, packet_number, data: bytes):
        self.file.add_packet_data(packet_number=packet_number, data=data)

    def clear_file_data(self):
        self.file = None

