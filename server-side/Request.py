import struct
from enum import Enum


class RequestHeader:
    REQUEST_HEADER_SIZE = 23  # Fixed-size header (16 + 1 + 2 + 4 = 23 bytes)
    REQUEST_HEADER_UNPACK_FORMAT = '<16sBHI'  # Little-endian: 16s (client_id), B (version), H (code), I (payload_size)

    def __init__(self, client_id: bytes, client_version: int, code: int, payload_size: int):
        """
               Initializes a RequestHeader instance.

               Args:
                   client_id (bytes): Unique identifier for the client (16 bytes).
                   client_version (int): Version of the client.
                   code (int): Request code indicating the type of request.
                   payload_size (int): Size of the payload.
        """
        self.client_id = client_id
        self.client_version = client_version
        self.code = code
        self.payload_size = payload_size

    @classmethod
    def unpack_header(cls, header_data: bytes) -> 'RequestHeader':
        """
                Unpacks the header data from bytes into a RequestHeader instance.

                Args:
                    header_data (bytes): The raw bytes of the header.

                Returns:
                    RequestHeader: An instance of RequestHeader populated with the unpacked data.
        """
        client_id, version, code, payload_size = struct.unpack(RequestHeader.REQUEST_HEADER_UNPACK_FORMAT, header_data)
        RequestHeader(client_id, version, code, payload_size)
        print("Unpacking header of request code: " , code)
        return cls(client_id, version, code, payload_size)

    def get_payload_size(self):
        return self.payload_size


class Request:
    NAME_LENGTH_BYTES = 255
    def __init__(self, header, payload=b""):
        self.header = header
        self.payload = payload

    @staticmethod
    def receive_payload_bytes(conn, payload_size) -> bytes:
        """
               Receives payload bytes from the connection.

               Args:
                   conn: The connection object.
                   payload_size (int): The expected size of the payload.

               Returns:
                   bytes: The received payload bytes.
        """
        return conn.recv(payload_size)

    @staticmethod
    def receive_request_header(conn) -> RequestHeader:
        return RequestHeader.unpack_header(conn.recv(RequestHeader.REQUEST_HEADER_SIZE))


class ClientRequestPayloadSizes(Enum):
    REGISTER_REQUEST_PAYLOAD_SIZE = 255
    SEND_FILE_REQUEST_PAYLOAD_SIZE = 1291
    RECONNECTION_REQUEST_PAYLOAD_SIZE = 255
    SEND_FILE_REQUEST_HEADER_EXTRAS_SIZE = 267


class ClientRequestCodes(Enum):
    REGISTER_REQUEST = 825
    SEND_PUBLIC_KEY_REQUEST = 826
    RECONNECT_TO_SERVER_REQUEST = 827
    SEND_FILE_REQUEST = 828
    ADEQUATE_CRC_VALUE = 900
    INADEQUATE_CRC_VALUE = 901
    INADEQUATE_CRC_VALUE_FOR_THE_FORTH_TIME = 902


class RequestPayloadFormats(Enum):
    SEND_PUBLIC_KEY_REQUEST_FORMAT = "255s 160s"  # 255 bytes - Name, 160 bytes - Public key

    # < - little-endian, I -  (unsigned int) 4 bytes - Content size, I - (unsigned int) Orig file size,
    # H - unsigned short (2 bytes) - packet number, H - unsigned short (2 bytes) - total packets,
    # 255 bytes - File name
    SEND_FILE_REQUEST_PAYLOAD_FORMAT = '<I I H H 255s 1024s'


def receive_public_key(conn, username, uuid:bytes):
    """
       Receives and validates the public key sent by the client.

       Args:
           conn: The connection object.
           username (str): The expected username of the client.
           uuid (bytes): The expected UUID of the client.

       Returns:
           bytes: The public key sent by the client.

       Raises:
           ValueError: If the received parameters do not match expected values.
    """
    header = Request.receive_request_header(conn=conn)

    if header.code != ClientRequestCodes.SEND_PUBLIC_KEY_REQUEST.value or header.client_id != uuid:
        raise ValueError("Invalid parameters received in expected SEND_PUBLIC_KEY_REQUEST_HEADER")

    payload_data = conn.recv(header.payload_size)
    payload_format = RequestPayloadFormats.SEND_PUBLIC_KEY_REQUEST_FORMAT.value
    received_username, public_key = struct.unpack(payload_format, payload_data)

    received_username = received_username.decode('utf-8').rstrip('\x00')  # Convert bytes to string and strip null bytes
    if received_username != username:
        raise ValueError("Invalid parameters received in expected SEND_PUBLIC_KEY_REQUEST_PAYLOAD")

    return public_key


def receive_client_crc_conformation_message(conn, file_name, client_id:bytes):
    """
        Receives and validates the CRC confirmation message from the client.

        Args:
            conn: The connection object.
            file_name (str): The expected file name for the received file.
            client_id (bytes): The expected client ID.

        Returns:
            int: The received CRC confirmation code.

        Raises:
            ValueError: If any validation checks fail.
    """
    # client_crc_conformation_message_length = 278 =
    # client_id -> 16 bytes + version -> 1 byte  + Code -> 2 bytes + payload size -> 4 bytes + file_name -> 255 bytes
    header = Request.receive_request_header(conn=conn)
    payload = Request.receive_payload_bytes(conn=conn, payload_size=header.payload_size)
    received_file_name = payload.decode("utf-8").rstrip('\x00')

    # Check if client_id and file_name match
    if header.client_id != client_id:
        raise ValueError("Client ID does not match the expected value.")
    if received_file_name != file_name:
        raise ValueError("File name does not match the expected value.")
    if header.payload_size != Request.NAME_LENGTH_BYTES:
        raise ValueError("Username does not match the expected value.")
    print(header.code)
    if header.code != ClientRequestCodes.ADEQUATE_CRC_VALUE.value and header.code != ClientRequestCodes.INADEQUATE_CRC_VALUE.value and ClientRequestCodes.INADEQUATE_CRC_VALUE_FOR_THE_FORTH_TIME.value:
        raise ValueError("CRC conformation Code does not match the expected value.")
    return header.code
