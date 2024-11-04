#include "utils.hpp"
#include "requests.hpp"

RegisterRequest::RegisterRequest(RequestHeader header, RegistrationPayload payload)
	: Request(header), payload(payload) {}

const RegistrationPayload* RegisterRequest::getPayload() const {
	return &payload;  // Returning a pointer to payload
}


/*
	This method packs the header and payload for the registration request in a form of uint8_t vector
	All numeric fields are ordered by little endian order
*/
Bytes RegisterRequest::pack_request() const {
	Bytes packed_header = this->getHeader().pack_header();
	Bytes packed_payload = this->getPayload()->pack_payload();
	Bytes request = packed_header + packed_payload;
	return request;
}


/** RegisterRequest::run
 * Sends a registration request to the server and handles the response.
 *
 * This function performs the following steps:
 * 1. Packs the registration request fields into a byte vector.
 * 2. Attempts to send the request to the server via the provided socket.
 * 3. Receives the response header from the server, extracting the response code
 *    and the size of the response payload.
 * 4. Receives the response payload and checks for errors in the response.
 *    - If the response code indicates failure or if the payload size is incorrect,
 *      an exception is thrown.
 * 5. If the registration is successful, it sets the UUID from the server's response.
 * 6. The function will retry sending the request up to a maximum number of attempts
 *    defined by `MAX_REQUEST_FAILS`.
 * 7. Returns `SUCCESS` if the registration was successful, or `FAILURE` if the maximum
 *    number of attempts is reached without a successful registration.
 *
 * @param sock A reference to the TCP socket used for communication with the server.
 * @return An integer indicating the result of the registration attempt (SUCCESS or FAILURE).
 */

int RegisterRequest::run(tcp::socket& sock) {
	// Pack request fields into vector and initialize parameter times_sent to 0
	int times_sent = 1;
	Bytes request = this->pack_request();

	while (times_sent <= MAX_REQUEST_FAILS) {
		try {
			// Send the request to the server via the provided socket
			boost::asio::write(sock, boost::asio::buffer(request));

			// Receiving the header from the server, extracting response code and header_extras_size
			Bytes response_header(RESPONSE_HEADER_SIZE);
			boost::asio::read(sock, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));
			uint16_t response_code = extractCodeFromResponseHeader(response_header);
			uint32_t response_payload_size = extractPayloadSizeFromResponseHeader(response_header);

			// Receiving the payload from the server and saving the num of bytes received from it
			Bytes response_payload(response_payload_size);
			size_t num_of_bytes_received_from_server = boost::asio::read(sock, boost::asio::buffer(response_payload, response_payload_size));

			// If the code is wrong or we didn't receive enough bytes or the payload size we got is wrong
			if (response_code != Codes::REGISTRATION_SUCCEEDED_CODE || response_payload_size != PayloadSize::REGISTRATION_SUCCEEDED_PAYLOAD_SIZE || num_of_bytes_received_from_server != response_payload_size) {
				throw std::invalid_argument("server responded with an error");
			}
			// The Registration succeeded, set the uuid to the id the server responded with
			this->header.setUUIDFromRawBytes(response_payload);
			//this->getHeaderReference().setUUIDFromRawBytes(response_payload);

			break; // Existing the loop Registration was successful
		}
		catch (std::exception& e) {
			std::cerr << e.what() << std::endl;
		}

		times_sent++; // Meaning we failed registering 1 time because we catched an exception 
	}

	// If the times_sent reached MAX_REQUEST_FAILS, returning false
	if (times_sent >= MAX_REQUEST_FAILS) {
		return FAILURE;
	}
	// If the the registration succeeded, return true
	return SUCCESS;
}


SendPublicKeyRequest::SendPublicKeyRequest(RequestHeader header, SendPublicKeyPayload payload)
	: Request(header), payload(payload) {}

const SendPublicKeyPayload* SendPublicKeyRequest::getPayload() const {
	return &payload;  // Returning a pointer to payload
}

string SendPublicKeyRequest::getEncryptedAESKey() const {
	return payload.getEncryptedAESKey();
}
void SendPublicKeyRequest::updateEncryptedAESKey(const Bytes& encrypted_aes_key) {
	string encrypted_ase_key_string = string(encrypted_aes_key.begin(), encrypted_aes_key.end());
	this->payload.setEncryptedAESKey(encrypted_ase_key_string);
}


Bytes SendPublicKeyRequest::pack_request() const {
	Bytes packed_header = this->getHeader().pack_header();
	Bytes packed_payload = this->getPayload()->pack_payload();
	Bytes request = packed_header + packed_payload;
	return request;
}

/** SendPublicKeyRequest::run
 * Sends a public key to the server and processes the server's response.
 *
 * This function performs the following steps:
 * 1. Packs the public key request fields into a byte vector.
 * 2. Attempts to send the request to the server via the provided socket.
 * 3. Receives the response header from the server, extracting the response code
 *    and the size of the response payload.
 * 4. Receives the response payload and checks for errors in the response.
 *    - If the response code indicates failure, or if the payload size is incorrect,
 *      an exception is thrown.
 * 5. Validates that the UUID in the response matches the client's UUID.
 * 6. Extracts the encrypted AES key from the response payload.
 * 7. Handles cases where the length of the extracted key does not match the expected size.
 * 8. The function will retry sending the request up to a maximum number of attempts
 *    defined by `MAX_REQUEST_FAILS`.
 * 9. Returns `SUCCESS` if the request was successful, or `FAILURE` if the maximum
 *    number of attempts is reached without success.
 *
 * @param sock A reference to the TCP socket used for communication with the server.
 * @return An integer indicating the result of the public key sending attempt (SUCCESS or FAILURE).
 */

int SendPublicKeyRequest::run(tcp::socket& sock) {
	// Pack request fields into vector and initialize parameter times_sent to 0
	int times_sent = 1;
	Bytes request = pack_request();

	while (times_sent <= MAX_REQUEST_FAILS) {
		try {
			// Send the request to the server via the provided socket
			boost::asio::write(sock, boost::asio::buffer(request));

			// Receive header from the server, get response code and header_extras_size
			Bytes response_header(RESPONSE_HEADER_SIZE);
			boost::asio::read(sock, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));
			uint16_t response_code = extractCodeFromResponseHeader(response_header);
			uint32_t response_payload_size = extractPayloadSizeFromResponseHeader(response_header);

			// Receive payload from the server, save it's length in parameter length
			Bytes response_payload(response_payload_size);
			size_t length = boost::asio::read(sock, boost::asio::buffer(response_payload, response_payload_size));

			// If the code is not success, the header_extras_size for the code is not the same as the size received in the header, or the length of the payload is not the wanted length, print error
			if (response_code != Codes::PUBLIC_KEY_RECEIVED_CODE || length != response_payload_size || response_payload_size != PayloadSize::PUBLIC_KEY_RECEIVED_PAYLOAD_SIZE) {
				throw std::invalid_argument("server responded with an error");
			}

			// Copy the id from the payload, and check if it's the correct client id
			Bytes payload_uuid(UUID_SIZE);
			std::copy(response_payload.begin(), response_payload.begin() + UUID_SIZE, payload_uuid.begin());

			if (!are_uuids_equal(payload_uuid, this->getHeader().getUUID())) {
				throw std::invalid_argument("server responded with an error");
			}

			Bytes encrypted_aes_key(ENCRYPTED_AES_KEY_LENGTH);
			std::copy(response_payload.begin() + UUID_SIZE, response_payload.end(), encrypted_aes_key.begin());

			// If the copied key is smaller than expected, handle it here
			if (encrypted_aes_key.size() != ENCRYPTED_AES_KEY_LENGTH) {
				throw std::out_of_range("Not enough bytes or too many bytes to fill the encrypted AES key");
			}

			updateEncryptedAESKey(encrypted_aes_key);

			break; // Existing the loop SendPublicKeyRequest::run was successful
		}
		catch (std::exception& e) {
			std::cerr << e.what() << std::endl;
		}
		// Increment the i by 1 each iteration.
		times_sent++;
	}
	// If the times_sent reached MAX_REQUEST_FAILS, returning false
	if (times_sent >= MAX_REQUEST_FAILS) {
		return FAILURE;
	}
	// If the the SendPublicKeyRequest::run succeeded, return true
	return SUCCESS;
}



ReconnectRequest::ReconnectRequest(RequestHeader header, ReconnectionPayload payload)
	: Request(header), payload(payload) {}

const ReconnectionPayload* ReconnectRequest::getPayload() const {
	return &payload;  // Returning a pointer to payload
}

Bytes ReconnectRequest::pack_request() const { //todo :not done
	Bytes packed_header = this->getHeader().pack_header();
	Bytes packed_payload = this->getPayload()->pack_payload();
	Bytes request = packed_header + packed_payload;
	return request;
}


void ReconnectRequest::updateEncryptedAESKey(const Bytes& encrypted_aes_key) {
	this->payload.setEncryptedAESKey(reinterpret_cast<const char*>(encrypted_aes_key.data()), encrypted_aes_key.size());
}

/** ReconnectRequest::run
 * Sends a reconnection request to the server and processes the server's response.
 *
 * This function performs the following steps:
 * 1. Packs the reconnection request fields into a byte vector.
 * 2. Attempts to send the request to the server via the provided socket.
 * 3. Receives the response header from the server, extracting the response code
 *    and the size of the response payload.
 * 4. Receives the response payload and checks for errors in the response.
 *    - If the response indicates a failure (RECONNECTION_FAILED_CODE), it updates
 *      the client's UUID from the response payload and returns REGISTERED_NOT_RECONNECTED.
 *    - If the response indicates success (RECONNECTION_SUCCEEDED_CODE), it validates
 *      that the UUID matches the client's UUID and extracts the encrypted AES key.
 * 5. Handles exceptions and retries sending the request up to a maximum number of attempts
 *    defined by `MAX_REQUEST_FAILS`.
 * 6. Returns `SUCCESS` if the reconnection was successful, or `FAILURE` if the maximum
 *    number of attempts is reached without success.
 *
 * @param sock A reference to the TCP socket used for communication with the server.
 * @return An integer indicating the result of the reconnection attempt (SUCCESS, FAILURE, or REGISTERED_NOT_RECONNECTED).
 */
int ReconnectRequest::run(tcp::socket& sock) {
	// Pack request fields into vector and initialize parameter times_sent to 1
	int times_sent = 1;
	Bytes request = pack_request();

	while (times_sent <= MAX_REQUEST_FAILS) {
		cout << "times sent = " << times_sent << "\n";
		try {
			// Send the request to the server via the provided socket
			boost::asio::write(sock, boost::asio::buffer(request));

			// Receive header from the server, get response code and header_extras_size
			Bytes response_header(RESPONSE_HEADER_SIZE);
			boost::asio::read(sock, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));
			uint16_t response_code = extractCodeFromResponseHeader(response_header);
			uint32_t response_payload_size = extractPayloadSizeFromResponseHeader(response_header);
			// Receive payload from the server, save it's length in a parameter length
			Bytes response_payload(response_payload_size);
			size_t length = boost::asio::read(sock, boost::asio::buffer(response_payload, response_payload_size));
			// The reconnection FAILED, so it registerd a new user and returned us a new uuid
			if (response_code == Codes::RECONNECTION_FAILED_CODE && response_payload_size == PayloadSize::RECONNECTION_FAILED_PAYLOAD_SIZE && length == response_payload_size) {
				this->getHeaderReference().setUUIDFromRawBytes(response_payload);
				return REGISTERED_NOT_RECONNECTED;
			}
			// If the code is not success, or other problem occurred
			else if (response_code != Codes::RECONNECTION_SUCCEEDED_CODE || response_payload_size != PayloadSize::RECONNECTION_SUCCEEDED_PAYLOAD_SIZE_WITHOUT_AES_KEY_SIZE || length != response_payload_size) {
				throw std::invalid_argument("server responded with an error");
			}
			Bytes payload_uuid(UUID_SIZE);
			std::copy(response_payload.begin(), response_payload.begin() + UUID_SIZE, payload_uuid.begin());
			if (!are_uuids_equal(payload_uuid, this->getHeader().getUUID())) {
				throw std::invalid_argument("server responded with an error");
			}
			Bytes encrypted_aes_key(ENCRYPTED_AES_KEY_LENGTH);
			std::copy(response_payload.begin() + UUID_SIZE, response_payload.end(), encrypted_aes_key.begin());
			// Copy the encrypted aes key content from the response_payload vector into the parameter encrypted_aes_key, then break from the loop.
			updateEncryptedAESKey(encrypted_aes_key);
			break;
		}
		catch (std::exception& e) {
			std::cerr << e.what() << std::endl;
		}
		// Increment the i by 1 each iteration.
		times_sent++;
	}
	// If the times_sent reached MAX_REQUEST_FAILS, returning FAILURE
	if (times_sent >= MAX_REQUEST_FAILS) {
		return FAILURE;
	}
	// If the the SendPublicKeyRequest::run succeeded, return SUCCESS
	return SUCCESS;
}



ValidCrcRequest::ValidCrcRequest(RequestHeader header, ValidCrcPayload payload)
	: Request(header), payload(payload) {}


const ValidCrcPayload* ValidCrcRequest::getPayload() const {
	return &payload;
}

Bytes ValidCrcRequest::pack_request() const {
	Bytes packed_header = this->getHeader().pack_header();
	Bytes packed_payload = this->getPayload()->pack_payload();
	Bytes request = packed_header + packed_payload;
	return request;
}
/** ValidCrcRequest::run
 * Sends a valid CRC request to the server and processes the server's response.
 *
 * This function performs the following actions:
 * 1. Packs the valid CRC request fields into a byte vector.
 * 2. Attempts to send the request to the server using the provided socket.
 * 3. Receives the response header from the server, extracting the response code
 *    and the size of the response payload.
 * 4. Receives the response payload and checks for errors in the response:
 *    - If the response code indicates success, and the payload size matches the expected size,
 *      it validates that the UUID in the payload matches the client's UUID.
 * 5. Handles exceptions and retries sending the request up to a maximum number of attempts
 *    defined by `MAX_REQUEST_FAILS`.
 * 6. Returns `SUCCESS` if the request was successful, or `FAILURE` if the maximum
 *    number of attempts is reached without success.
 *
 * @param sock A reference to the TCP socket used for communication with the server.
 * @return An integer indicating the result of the CRC validation request (SUCCESS or FAILURE).
 */
int ValidCrcRequest::run(tcp::socket& sock) {
	int times_sent = 0;
	Bytes request = pack_request();

	while (times_sent < MAX_REQUEST_FAILS) {
		try {
			// Send the request to the server via the provided socket.
			boost::asio::write(sock, boost::asio::buffer(request));

			// Receive header from the server, get response code and payload_size
			Bytes response_header(RESPONSE_HEADER_SIZE);
			boost::asio::read(sock, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));
			uint16_t response_code = extractCodeFromResponseHeader(response_header);
			uint32_t response_payload_size = extractPayloadSizeFromResponseHeader(response_header);

			// Receive payload from the server, save it's length in a parameter length.
			Bytes response_payload(response_payload_size);
			size_t length = boost::asio::read(sock, boost::asio::buffer(response_payload, response_payload_size));

			// If the code is not success, the payload_size for the code is not the same as the size received in the header, or the length of the payload is not the wanted length, print error.
			if (response_code != Codes::FILE_RECEIVED_CRC_CODE || response_payload_size != PayloadSize::FILE_RECEIVED_CRC_PAYLOAD_SIZE || length != response_payload_size) {
				throw std::invalid_argument("server responded with an error");
			}

			//// Copy the id from the payload, and check if it's the correct client id.
			Bytes payload_uuid(UUID_SIZE);
			std::copy(response_payload.begin(), response_payload.begin() + UUID_SIZE, payload_uuid.begin());

			if (!are_uuids_equal(payload_uuid, this->getHeader().getUUID())) {
				throw std::invalid_argument("server responded with an error");
			}

			// If the id provided by the server is correct, break from the loop and return SUCCESS.
			break;
		}
		catch (std::exception& e) {
			std::cerr << e.what() << std::endl;
		}
		// Increment by 1 each iteration.
		times_sent++;
	}
	// If reached 3, return FAILURE.
	if (times_sent > MAX_REQUEST_FAILS) {
		return FAILURE;
	}
	// If the client succeeded, return SUCCESS.
	return SUCCESS;
}


InvalidCrcRequest::InvalidCrcRequest(RequestHeader header, InvalidCrcPayload payload)
	: Request(header), payload(payload) {}

const InvalidCrcPayload* InvalidCrcRequest::getPayload() const {
	return &payload;
}

Bytes InvalidCrcRequest::pack_request() const {
	Bytes packed_header = this->getHeader().pack_header();
	Bytes packed_payload = this->getPayload()->pack_payload();
	Bytes request = packed_header + packed_payload;
	return request;
}
/** InvalidCrcRequest::run
 * Sends an invalid CRC request to the server.
 *
 * This function performs the following actions:
 * 1. Packs the invalid CRC request fields into a byte vector.
 * 2. Attempts to send the request to the server using the provided socket.
 * 3. If the request is successfully sent, it returns `SUCCESS`.
 * 4. If an exception occurs during the send operation, it catches the exception,
 *    logs the error message, and returns `FAILURE`.
 *
 * @param sock A reference to the TCP socket used for communication with the server.
 * @return An integer indicating the result of the invalid CRC request (SUCCESS or FAILURE).
 */

int InvalidCrcRequest::run(tcp::socket& sock) {
	// Pack request fields into vector.
	Bytes request = pack_request();

	try {
		// Send the request to the server via the provided socket.
		boost::asio::write(sock, boost::asio::buffer(request));
	}
	catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		return FAILURE;
	}

	return SUCCESS;
}



InvalidCrcDoneRequest::InvalidCrcDoneRequest(RequestHeader header, InvalidCrcDonePayload payload)
	: Request(header), payload(payload) {}

const InvalidCrcDonePayload* InvalidCrcDoneRequest::getPayload() const {
	return &payload;
}

Bytes InvalidCrcDoneRequest::pack_request() const {
	Bytes packed_header = this->getHeader().pack_header();
	Bytes packed_payload = this->getPayload()->pack_payload();
	Bytes request = packed_header + packed_payload;
	return request;
}
/** InvalidCrcDoneRequest::run
 * Sends an invalid CRC done request to the server and waits for a response.
 *
 * This function executes the following steps:
 * 1. Packs the invalid CRC done request fields into a byte vector.
 * 2. Attempts to send the request to the server using the provided socket.
 * 3. Enters a loop to handle retries if the response is not successful.
 * 4. Receives the header from the server, extracting the response code and payload size.
 * 5. Receives the payload from the server and checks if it matches the expected sizes.
 * 6. Validates the UUID from the response payload against the client's UUID.
 * 7. Returns `SUCCESS` if the request was successful and the UUIDs match; otherwise, returns `FAILURE` after the maximum retries.
 *
 * @param sock A reference to the TCP socket used for communication with the server.
 * @return An integer indicating the result of the invalid CRC done request (SUCCESS or FAILURE).
 */
int InvalidCrcDoneRequest::run(tcp::socket& sock) {
	int times_sent = 1;
	Bytes request = pack_request();

	while (times_sent <= MAX_REQUEST_FAILS) {
		try {
			// Send the request to the server via the provided socket.
			boost::asio::write(sock, boost::asio::buffer(request));

			// Receive header from the server, get response code and payload_size
			Bytes response_header(RESPONSE_HEADER_SIZE);
			boost::asio::read(sock, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));
			uint16_t response_code = extractCodeFromResponseHeader(response_header);
			uint32_t response_payload_size = extractPayloadSizeFromResponseHeader(response_header);

			// Receive payload from the server, save it's length in a parameter length.
			Bytes response_payload(response_payload_size);
			size_t length = boost::asio::read(sock, boost::asio::buffer(response_payload, response_payload_size));

			// If the code is not success, the payload_size for the code is not the same as the size received in the header, or the length of the payload is not the wanted length, print error.
			if (response_code != Codes::FILE_RECEIVED_CRC_CODE || response_payload_size != PayloadSize::FILE_RECEIVED_CRC_PAYLOAD_SIZE || length != response_payload_size) {
				throw std::invalid_argument("server responded with an error");
			}

			//// Copy the id from the payload, and check if it's the correct client id.
			Bytes payload_uuid(UUID_SIZE);
			std::copy(response_payload.begin(), response_payload.begin() + UUID_SIZE, payload_uuid.begin());

			if (!are_uuids_equal(payload_uuid, this->getHeader().getUUID())) {
				throw std::invalid_argument("server responded with an error");
			}

			// If the id provided by the server is correct, break from the loop and return SUCCESS.
			break;
		}
		catch (std::exception& e) {
			std::cerr << e.what() << std::endl;
		}
		// Increment by 1 each iteration.
		times_sent++;
	}
	// If reached 3, return FAILURE.
	if (times_sent >= MAX_REQUEST_FAILS) {
		return FAILURE;
	}
	// If the client succeeded, return SUCCESS.
	return SUCCESS;
}



SendFileRequest::SendFileRequest(RequestHeader header, SendFilePayload payload)
	: Request(header), payload(payload) {}

const SendFilePayload* SendFileRequest::getPayload() const {
	return &payload;
}

SendFilePayload& SendFileRequest::getPayloadReference() {
	return payload; // Return a reference to the payload
}


//This is a special request where I need to send the request in chunks of data because
// the file could be too big
Bytes SendFileRequest::pack_request(const Bytes message_content) const {
	Bytes packed_header = this->getHeader().pack_header();
	Bytes packed_payload = this->getPayload()->pack_payload(message_content);
	Bytes request = packed_header + packed_payload;
	return request;
}

/** SendFileRequest::sendFileData
 * Sends the encrypted file data to the server in packets.
 *
 * This function executes the following steps:
 * 1. Retrieves the encrypted file content and its size.
 * 2. Iterates over the total number of packets to be sent.
 * 3. For each packet:
 *    - Calculates the starting and ending positions for the current packet in the file data.
 *    - Copies the relevant portion of the file content into a byte array.
 *    - Packs the packet and sends it to the server using the provided socket.
 * 4. If an exception occurs during the sending process, it logs the error and increments the attempt counter.
 * 5. If the maximum number of send attempts is reached without success, it returns `FAILURE`.
 * 6. If all packets are sent successfully, it returns `SUCCESS`.
 *
 * @param sock A reference to the TCP socket used for communication with the server.
 * @return An integer indicating the result of the file sending operation (SUCCESS or FAILURE).
 */
int SendFileRequest::sendFileData(tcp::socket& sock) {
	// Pack request fields into vector and initialize parameter times_sent to 1
	int times_sent = 1;
	string file_to_send = this->getPayload()->get_encrypted_file_content();
	size_t file_size = file_to_send.size();

	try {
		for (int packet_number = 0; packet_number < this->getPayload()->get_total_packets(); packet_number++) {
			// Calculate the starting position for the current packet
			size_t start = packet_number * CONTENT_SIZE_PER_PACKET;

			size_t end = std::min(start + CONTENT_SIZE_PER_PACKET, file_size);
			Bytes message_content(CONTENT_SIZE_PER_PACKET);
			std::copy(file_to_send.begin() + start, file_to_send.begin() + end, message_content.begin());
			// Bytes message_content(file_to_send.begin() + start, file_to_send.begin() + start + CONTENT_SIZE_PER_PACKET); // Extract the message content for the current packet
			this->getPayloadReference().set_packet_number(packet_number);
			Bytes request_packet = pack_request(message_content);
			boost::asio::write(sock, boost::asio::buffer(request_packet));
		}
	}
	catch (std::exception& error) {
		std::cerr << "Error sending data: " << error.what() << std::endl;
		++times_sent;
	}
	// If the times_sent reached MAX_REQUEST_FAILS, returning FAILURE
	if (times_sent >= MAX_REQUEST_FAILS) {
		return FAILURE;
	}
	// If the the sendFileData succeeded, return SUCCESS
	return SUCCESS;

}

/** SendFileRequest::run
 * Executes the file sending request to the server.
 *
 * This function performs the following steps:
 * 1. Attempts to send the file data to the server up to a maximum number of retries.
 * 2. After sending the file, it waits for a response from the server.
 * 3. Validates the response header and payload to ensure the file was received correctly.
 * 4. Checks the UUID and content size from the response to confirm successful processing.
 * 5. Extracts the file name and checksum from the response.
 * 6. Returns `FAILURE` if the maximum number of attempts is reached or if any validation fails; otherwise, returns `SUCCESS`.
 *
 * @param sock A reference to the TCP socket used for communication with the server.
 * @return An integer indicating the result of the file sending operation (SUCCESS or FAILURE).
 */
int SendFileRequest::run(tcp::socket& sock)
{
	int times_sent = 1;
	int sent_file;

	while (times_sent <= MAX_REQUEST_FAILS) {
		try {
			sent_file = sendFileData(sock);

			if (sent_file == FAILURE) {
				throw std::invalid_argument("Error sending file to server");
			}

			Bytes response_header(RESPONSE_HEADER_SIZE);
			boost::asio::read(sock, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));
			uint16_t response_code = extractCodeFromResponseHeader(response_header);
			uint32_t response_payload_size = extractPayloadSizeFromResponseHeader(response_header);

			// Receive payload from the server, save it's length in a parameter length.
			Bytes response_payload(response_payload_size);
			size_t length = boost::asio::read(sock, boost::asio::buffer(response_payload, response_payload_size));

			// If the code is not success, the payload_size for the code is not the same as the size received in the header, or the length of the payload is not the wanted length, print error.
			if (response_code != Codes::FILE_RECEIVED_CRC_CODE || response_payload_size != PayloadSize::FILE_RECEIVED_CRC_PAYLOAD_SIZE || length != response_payload_size) {
				throw std::invalid_argument("server responded with an error");
			}

			Bytes payload_uuid(UUID_SIZE);
			std::copy(response_payload.begin(), response_payload.begin() + UUID_SIZE, payload_uuid.begin());

			if (!are_uuids_equal(payload_uuid, this->getHeader().getUUID())) {
				throw std::invalid_argument("server responded with an error");
			}

			uint32_t response_content_size = extractPayloadContentSize(response_payload);
			if (this->getPayload()->get_content_size() != response_content_size) {
				throw std::invalid_argument("server responded with an error");
			}

			// std::string response_file_name(response_payload.begin() + sizeof(uuid) + sizeof(content_size), response_payload.begin() + sizeof(uuid) + sizeof(content_size) + sizeof(file_name));
			string response_file_name = extractSendFileResponseFileName(response_payload);
			if (response_file_name != string(this->getPayload()->get_file_name())) {
				throw std::invalid_argument("server responded with an error");
			}

			// Copy the cksum content from the response_payload vector into the parameter cksum.
			unsigned long response_cksum = extractSendFileResponseCksum(response_payload);

			this->getPayloadReference().setCksum(response_cksum);

			// continue here to get the responses
			break;
		}
		catch (std::exception& e) {
			std::cerr << e.what() << std::endl;
			++times_sent;
		}
	}



	// If the times_sent reached MAX_REQUEST_FAILS, returning FAILURE
	if (times_sent >= MAX_REQUEST_FAILS) {
		return FAILURE;
	}
	// If the the SendPublicKeyRequest::run succeeded, return SUCCESS
	return SUCCESS;
}

