import struct
from abc import abstractmethod

from Crypto.PublicKey import RSA

import Response
from Request import ClientRequestCodes, receive_public_key, ClientRequestPayloadSizes, RequestHeader, \
    RequestPayloadFormats, receive_client_crc_conformation_message
from CryptoUtils import compute_new_aes_key, encrypt_aes_key_with_public_key
from Request import Request


class Protocol:
    def __init__(self, server, conn):
        self.server = server
        self.conn = conn

    @abstractmethod
    def protocol(self, header: RequestHeader):
        """
               Abstract method for handling protocol-specific logic.

               Args:
                   header (RequestHeader): The header containing request information.
        """
        pass


class RegisterRequestProtocol(Protocol):
    def __init__(self, server, conn):
        super().__init__(server, conn)

    def protocol(self, header: RequestHeader):
        """
               Handles the registration protocol.

               Args:
                   header (RequestHeader): The header containing request information.
        """
        print("Initiating RegisterRequestProtocol!")
        try:
            payload = Request.receive_payload_bytes(conn=self.conn,
                                                    payload_size=ClientRequestPayloadSizes.REGISTER_REQUEST_PAYLOAD_SIZE.value)
            username = payload[:255].decode('utf-8').rstrip('\x00')

            if not self.server.get_database().is_username_already_registered(username):
                uuid = self.server.get_database().add_new_user_to_database(username=username)
                Response.send_register_success_response(self, uuid)
            else:
                raise Exception("User already exists in database trying to register")

        except Exception as error:
            print(error)
            Response.send_registration_failed_response(self)
            return  # Exiting in case of failure
        try:
            public_key_bytes = receive_public_key(conn=self.conn, username=username, uuid=uuid)
            public_key = RSA.import_key(public_key_bytes)
            self.server.get_database().set_new_user_public_key(username=username, public_key=public_key)
            aes_key = self.server.get_database().get_user_by_uuid(uuid).get_aes_key()
            encrypted_aes_key = encrypt_aes_key_with_public_key(aes_key=aes_key, public_key=public_key)
            Response.send_encrypted_aes_key_response(self, uuid, encrypted_aes_key)

        except Exception as error:
            print(error)
            Response.send_general_server_error(self)


class SendFileRequestProtocol(Protocol):
    def __init__(self, server, conn):
        super().__init__(server, conn)

    def protocol(self, header: RequestHeader):
        """
               Handles the file sending protocol.

               Args:
                   header (RequestHeader): The header containing request information.
        """
        try:
            if self.server.get_database().does_uuid_already_exist(header.client_id):
                payload = Request.receive_payload_bytes(conn=self.conn, payload_size=header.payload_size)
                payload_dict = self.get_payload_dict(payload)
                self.server.get_database().save_user_file_data(header.client_id, payload_dict)
                user = self.server.get_database().get_user_by_uuid(header.client_id)
                if not user.received_entire_file():
                    header = Request.receive_request_header(conn=self.conn)
                    if header.client_id != user.get_uuid() or header.code != ClientRequestCodes.SEND_FILE_REQUEST.value:
                        Response.send_general_server_error(self)
                        return
                    self.protocol(header=header)
                    return

                user.get_file().decrypt_and_write_file_data_to_memory(aes_key=user.get_aes_key())
                file_crc = user.get_file().get_crc()
                encrypted_content_size = user.get_file().get_encrypted_content_size()
                Response.send_file_received_crc_response(
                    self, client_id=header.client_id,
                    encrypted_content_size=encrypted_content_size,
                    message_file_name=payload_dict["file_name"],
                    file_checksum_value=file_crc)

                # Receiving the client crc conformation code
                crc_conformation_code = receive_client_crc_conformation_message(
                    conn=self.conn, file_name=payload_dict["file_name"],
                    client_id=header.client_id)

                # Handling the conformation code we got
                self.handle_crc_conformation_code(crc_conformation_code=crc_conformation_code,
                                                  client_id=header.client_id)
            else:
                raise KeyError("UUID doesn't exist in database, tried to initiate send file protocol")

        except OSError as error:
            print(error)
            Response.send_general_server_error(self)
        print("FINISHED METHOD")
    @staticmethod
    def get_payload_dict(payload: bytes):
        """
               Unpacks the payload bytes into a structured dictionary.

               Args:
                   payload (bytes): The raw bytes received from the client.

               Returns:
                   dict: A dictionary containing the unpacked data, including content size,
                         original file size, packet number, total packets, file name, and message content.
        """
        # Unpack the first 265 bytes (the header extras)
        payload_format = RequestPayloadFormats.SEND_FILE_REQUEST_PAYLOAD_FORMAT.value
        header_extras_size = ClientRequestPayloadSizes.SEND_FILE_REQUEST_HEADER_EXTRAS_SIZE.value
        unpacked_data = struct.unpack(payload_format, payload)
        content_size, orig_file_size, packet_number, total_packets, file_name_bytes, content = unpacked_data

        file_name = file_name_bytes.decode('utf-8').rstrip('\x00')  # Clean null termination

        # Return the unpacked header data and the remaining payload (message content)
        return {
            'content_size': content_size,
            'orig_file_size': orig_file_size,
            'packet_number': packet_number,
            'total_packets': total_packets,
            'file_name': file_name,
            'message_content': payload[header_extras_size:]
        }

    def handle_crc_conformation_code(self, crc_conformation_code, client_id):
        """
               Handles the CRC confirmation code received from the client.

               Args:
                   crc_conformation_code: The confirmation code received from the client.
                   client_id: The UUID of the client.

               Raises:
                   ValueError: If the confirmation code does not match any expected values.
        """
        print("Handle CRC")
        if crc_conformation_code == ClientRequestCodes.ADEQUATE_CRC_VALUE.value:
            Response.send_receive_message_thanks_response(self, client_id=client_id)
        elif crc_conformation_code == ClientRequestCodes.INADEQUATE_CRC_VALUE.value:
            return
        elif crc_conformation_code == ClientRequestCodes.INADEQUATE_CRC_VALUE_FOR_THE_FORTH_TIME.value:
            self.server.get_database().get_user_by_uuid(client_id).clear_file_data()
            Response.send_receive_message_thanks_response(self, client_id=client_id)
        else:  # The client replied with a crc conformation value that does not match any expected reply code
            self.server.get_database().get_user_by_uuid(client_id).clear_file_data()
            raise ValueError("Client replied with a crc conformation value that does not match any expected reply code")


class ReconnectionRequestProtocol(Protocol):
    def __init__(self, server, conn):
        super().__init__(server, conn)

    def protocol(self, header: RequestHeader):
        """
               Handles the reconnection protocol.

               Args:
                   header (RequestHeader): The header containing request information.

               Raises:
                   ValueError: If the reconnection request payload size is incorrect.
        """
        print("Initiating ReconnectionRequestProtocol!")
        try:
            if header.payload_size != ClientRequestPayloadSizes.RECONNECTION_REQUEST_PAYLOAD_SIZE.value:
                raise ValueError("Reconnection Request wrong payload size")

            payload = Request.receive_payload_bytes(conn=self.conn, payload_size=header.payload_size)
            username = payload.decode("utf-8").rstrip('\x00')

            if not self.server.get_database().is_username_already_registered(
                    username) or self.server.get_database().get_user_by_uuid(header.client_id).get_public_key() is None:

                self.server.get_database().remove_user_if_registered(username, header.client_id)
                self.register_user(username)
            else:
                aes_key = compute_new_aes_key()
                self.server.get_database().get_user_by_uuid(header.client_id).set_aes_key(aes_key)

                # Clear the packet dictionary.
                self.server.get_database().get_user_by_uuid(header.client_id).get_file().clear_dict()
                public_key = self.server.get_database().get_user_by_uuid(header.client_id).get_public_key()
                encrypted_aes_key = encrypt_aes_key_with_public_key(aes_key=aes_key, public_key=public_key)
                Response.send_reconnect_request_accepted_sending_aes_key_response(self, header.client_id,
                                                                                  encrypted_aes_key=encrypted_aes_key)

        except OSError as error:
            print(error)
            Response.send_general_server_error(self)
            return

    def register_user(self, username):
        """
                Registers a new user during the reconnection process.

                Args:
                    username (str): The username of the user to register.
        """
        uuid = self.server.get_database().add_new_user_to_database(username=username)
        Response.send_reconnect_request_has_been_rejected_response(self, uuid)

        public_key_bytes = receive_public_key(conn=self.conn, username=username, uuid=uuid)
        public_key = RSA.import_key(public_key_bytes)
        aes_key = self.server.get_database().get_user_by_uuid(uuid=uuid).get_aes_key()
        encrypted_aes_key = encrypt_aes_key_with_public_key(aes_key=aes_key, public_key=public_key)
        Response.send_encrypted_aes_key_response(self, uuid, encrypted_aes_key)
