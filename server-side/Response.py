import struct
from enum import Enum
from wsgiref.simple_server import server_version

from protocols import Protocol


class ResponseHeader:
    def __init__(self, server_version:int, response_code:int, payload_size=0):
        self.server_version = server_version
        self.response_code = response_code
        self.payload_size = payload_size

    def get_payload_size(self):
        return self.payload_size

    def pack_header(self):
        # struct format (That we pack the message header with):
        # '<' represents we are using a Little-Endian Format
        # 'B' represents an unsigned char (1 byte), 'H' represents unsigned short (2 bytes)
        # 'H' represents Unsigned short (2 bytes)
        # 'I' represents an unsigned int (4 bytes)
        return struct.pack('<B H I', self.server_version, self.response_code, self.payload_size)


class Response:
    def __init__(self, header:ResponseHeader, payload: bytes = b''):
        self.header = header
        self.payload = payload

    def pack_message_header_with_payload(self):
        return self.header.pack_header() + self.payload

    def response(self, conn):
        print("CODE RESPONDED WITH:", self.header.response_code)
        message = self.pack_message_header_with_payload()
        conn.sendall(message)


class ResponsesCodes(Enum):
    REGISTERED_SUCCESSFULLY = 1600
    REGISTRATION_FAILED = 1601
    PUBLIC_KEY_RECEIVED_SENDING_ENCRYPTED_AES_KEY = 1602
    FILE_RECEIVED_SUCCESSFULLY_WITH_CRC = 1603
    RECEIVE_MESSAGE_THANKS = 1604
    APPROVED_RECONNECT_REQUEST_SENDING_ENCRYPTED_AES_KEY = 1605
    DISAPPROVED_RECONNECT_REQUEST = 1606
    GENERAL_SERVER_ERROR = 1607


class ResponsesPayloadSize(Enum):
    REGISTER_REQUEST_RESPONSE_PAYLOAD_SIZE = 16
    # SEND_FILE_RECEIVED_CRC_PAYLOAD_SIZE =
    # 16 bytes (client_id) + 4 bytes (encrypted_content_size) + 255 bytes (file_name) + 4 bytes (checksum_value)
    # = 279 (payload size)
    SEND_FILE_RECEIVED_CRC_RESPONSE_PAYLOAD_SIZE = 279
    RECEIVE_MESSAGE_THANKS_PAYLOAD_SIZE = 255
    DISAPPROVED_RECONNECT_REQUEST_PAYLOAD_SIZE = 16
    APPROVED_RECONNECT_REQUEST_SENDING_ENCRYPTED_AES_KEY_PAYLOAD_SIZE = 144
    SEND_ENCRYPTED_AES_KEY_RESPONSE_PAYLOAD_SIZE = 144


class ResponsePayloadFormats(Enum):
    # SEND_FILE_RECEIVED_CRC_RESPONSE_PAYLOAD_FORMA =
    # 16 bytes for Client ID, 4 bytes for encrypted content Size, 255 bytes for File Name, 4 bytes for Checksum
    SEND_FILE_RECEIVED_CRC_RESPONSE_PAYLOAD_FORMAT = '<16s I 255s I'
    REGISTER_REQUEST_SUCCESS_PAYLOAD_FORMAT = '<16s'


def send_general_server_error(protocol_obj: Protocol):
    response = build_send_general_server_error_response(protocol_obj.server.get_version())
    response.response(protocol_obj.conn)


def build_send_general_server_error_response(server_version) -> Response:
    header = ResponseHeader(server_version=server_version, response_code=ResponsesCodes.GENERAL_SERVER_ERROR.value)
    response = Response(header)
    return response


def send_register_success_response(protocol_obj: Protocol, uuid:bytes):
    response = build_register_success_response(protocol_obj.server.get_version(), uuid)
    response.response(protocol_obj.conn)


def build_register_success_response(server_version, uuid:bytes) -> Response:
    header = ResponseHeader(server_version=server_version,
                            response_code=ResponsesCodes.REGISTERED_SUCCESSFULLY.value,
                            payload_size=ResponsesPayloadSize.REGISTER_REQUEST_RESPONSE_PAYLOAD_SIZE.value)
    payload_format = ResponsePayloadFormats.REGISTER_REQUEST_SUCCESS_PAYLOAD_FORMAT.value
    # The format string '<' indicates little-endian format.
    # '16s' means a string of 16 bytes
    payload = struct.pack(payload_format, uuid)
    response = Response(header=header, payload=payload)
    return response


def send_registration_failed_response(protocol_obj: Protocol):
    response = build_registration_failed_response(protocol_obj.server.get_version())
    response.response(protocol_obj.conn)


def build_registration_failed_response(server_version) -> Response:
    header = ResponseHeader(server_version=server_version,
                            response_code=ResponsesCodes.REGISTRATION_FAILED.value)
    response = Response(header)
    return response


def send_encrypted_aes_key_response(protocol_obj: Protocol, uuid:bytes, encrypted_aes_key:bytes):
    response = build_send_encrypted_aes_key_response(protocol_obj.server.get_version(), uuid, encrypted_aes_key)
    response.response(protocol_obj.conn)


def build_send_encrypted_aes_key_response(server_version, uuid:bytes, encrypted_aes_key:bytes) -> Response:
    header = ResponseHeader(server_version=server_version,
                            response_code=ResponsesCodes.PUBLIC_KEY_RECEIVED_SENDING_ENCRYPTED_AES_KEY.value,
                            payload_size=ResponsesPayloadSize.SEND_ENCRYPTED_AES_KEY_RESPONSE_PAYLOAD_SIZE.value)
    encrypted_aes_key_format_size = ResponsesPayloadSize.SEND_ENCRYPTED_AES_KEY_RESPONSE_PAYLOAD_SIZE.value - 16
    payload_format = f'16s{encrypted_aes_key_format_size}s'  # Create the format string based 16 byte uuid and the length of the encrypted_aes_key
    packed_payload = struct.pack(payload_format, uuid, encrypted_aes_key)
    return Response(header, packed_payload)


def send_file_received_crc_response(protocol_obj: Protocol, client_id:bytes, encrypted_content_size, message_file_name,
                                    file_checksum_value):
    response = build_send_file_received_crc_response(protocol_obj.server.get_version(), client_id,
                                                     encrypted_content_size, message_file_name,
                                                     file_checksum_value)
    response.response(protocol_obj.conn)


def build_send_file_received_crc_response(server_version, client_id:bytes, encrypted_content_size, message_file_name,
                                          file_checksum_value) -> Response:
    payload_size = ResponsesPayloadSize.SEND_FILE_RECEIVED_CRC_RESPONSE_PAYLOAD_SIZE.value
    payload_format = ResponsePayloadFormats.SEND_FILE_RECEIVED_CRC_RESPONSE_PAYLOAD_FORMAT.value
    header = ResponseHeader(server_version=server_version,
                            response_code=ResponsesCodes.FILE_RECEIVED_SUCCESSFULLY_WITH_CRC.value,
                            payload_size=payload_size)
    file_name_bytes = message_file_name.encode("utf-8")
    packed_payload = struct.pack(payload_format, client_id, encrypted_content_size, file_name_bytes,
                                 file_checksum_value)
    return Response(header, packed_payload)


def send_receive_message_thanks_response(protocol_obj: Protocol, client_id:bytes):
    response = build_receive_message_thanks_response(protocol_obj.server.get_version(), client_id)
    response.response(protocol_obj.conn)


def build_receive_message_thanks_response(server_version, client_id:bytes) -> Response:
    payload_size = ResponsesPayloadSize.RECEIVE_MESSAGE_THANKS_PAYLOAD_SIZE.value
    header = ResponseHeader(server_version=server_version,
                            response_code=ResponsesCodes.RECEIVE_MESSAGE_THANKS.value, payload_size=payload_size)

    payload = client_id
    response = Response(header, payload=payload)
    return response


def send_reconnect_request_has_been_rejected_response(protocol_obj: Protocol, client_id:bytes):
    response = build_reconnect_request_has_been_rejected_response(protocol_obj.server.get_version(), client_id)
    response.response(protocol_obj.conn)


def build_reconnect_request_has_been_rejected_response(server_version, client_id:bytes) -> Response:
    header = ResponseHeader(server_version=server_version,
                            response_code=ResponsesCodes.DISAPPROVED_RECONNECT_REQUEST.value,
                            payload_size=ResponsesPayloadSize.DISAPPROVED_RECONNECT_REQUEST_PAYLOAD_SIZE.value)

    payload = client_id
    response = Response(header, payload)
    return response


def send_reconnect_request_accepted_sending_aes_key_response(protocol_obj: Protocol, client_id:bytes, encrypted_aes_key:bytes):
    response = build_reconnect_request_accepted_sending_aes_key_response(
        server_version=protocol_obj.server.get_version(), client_id=client_id, encrypted_aes_key=encrypted_aes_key)

    response.response(protocol_obj.conn)


def build_reconnect_request_accepted_sending_aes_key_response(server_version, client_id:bytes, encrypted_aes_key:bytes) -> Response:
    header = ResponseHeader(server_version=server_version,
                            response_code=ResponsesCodes.APPROVED_RECONNECT_REQUEST_SENDING_ENCRYPTED_AES_KEY.value,
                            payload_size=ResponsesPayloadSize.APPROVED_RECONNECT_REQUEST_SENDING_ENCRYPTED_AES_KEY_PAYLOAD_SIZE.value)
    encrypted_aes_key_format_size = ResponsesPayloadSize.SEND_ENCRYPTED_AES_KEY_RESPONSE_PAYLOAD_SIZE.value - 16
    payload_format = f'16s{encrypted_aes_key_format_size}s'  # Create the format string based 16 byte uuid and the length of the encrypted_aes_key
    packed_payload = struct.pack(payload_format, client_id, encrypted_aes_key)
    response = Response(header, packed_payload)
    return response
