#include "requests_payloads.hpp"
#include "utils.hpp"

RegistrationPayload::RegistrationPayload(const string& username) {
	// Attempt to copy the username
	errno_t result = strcpy_s(this->username, MAX_USERNAME_LENGTH, username.c_str());
	if (result != 0) {
		std::cerr << "Error copying username in RegistrationPayload: source is too long!" << std::endl;
		// Handle the error appropriately, e.g., set username to an empty string
		this->username[0] = '\0'; // Ensure username is empty on error
	}
}

string RegistrationPayload::getUsername() const { return username; }

Bytes RegistrationPayload::pack_payload() const
{
	Bytes packed_payload(REGISTRATION_PAYLOAD_SIZE, 0); // Initialize with zeroes the packed_payload

	// Get the actual length of the username string (up to 255)
	size_t username_length = std::strlen(this->username);

	// Copy the username into the vector
	std::copy(this->username, this->username + std::min(username_length, size_t(REGISTRATION_PAYLOAD_SIZE)), packed_payload.begin());
	return packed_payload;
}


SendPublicKeyPayload::SendPublicKeyPayload(const string& username, const string& public_key) {
	// Copy the username
	errno_t result = strcpy_s(this->username, MAX_USERNAME_LENGTH, username.c_str());
	if (result != 0) {
		std::cerr << "Error copying username in SendPublicKeyPayload: source is too long!" << std::endl;
		this->username[0] = '\0'; // Ensure username is empty on error
	}

	// Copy the public key
	if (public_key.size() > PUBLIC_KEY_LENGTH) {
		std::cerr << "Error copying username in public key in SendPublicKeyPayload: source is too long!" << std::endl;
	}
	memcpy(this->public_key, public_key.c_str(), public_key.size());

	// Initialize encrypted_aes_key to an empty string
	this->encrypted_aes_key[0] = '\0';
}

string SendPublicKeyPayload::getUsername() const { return username; }

string SendPublicKeyPayload::getPublicKey() const { return public_key; }

string SendPublicKeyPayload::getEncryptedAESKey() const {
	string str_aes_key(encrypted_aes_key, encrypted_aes_key + sizeof(encrypted_aes_key));
	return str_aes_key;
}

void SendPublicKeyPayload::setEncryptedAESKey(string encrypted_aes_key) {
	if (encrypted_aes_key.size() > ENCRYPTED_AES_KEY_LENGTH) {
		throw std::out_of_range("Encrypted AES key is too long");
	}

	// Use memcpy to copy the string into the char array
	std::memcpy(this->encrypted_aes_key, encrypted_aes_key.c_str(), encrypted_aes_key.size());
}


Bytes SendPublicKeyPayload::pack_payload() const {

	constexpr size_t NUM_OF_BYTES_OF_USERNAME = 255;
	constexpr size_t NUM_OF_BYTES_OF_PUBLIC_KEY = 160;

	// Initialize the packed payload with zeroes and in the correct size
	Bytes packed_payload(NUM_OF_BYTES_OF_USERNAME + NUM_OF_BYTES_OF_PUBLIC_KEY, 0);

	// Get the actual length of the username string
	size_t name_length = std::strlen(this->username);

	// Copy the username into the vector, limiting to the maximum size
	std::copy(this->username, this->username + std::min(name_length, size_t(NUM_OF_BYTES_OF_USERNAME)), packed_payload.begin());

	// Copy the public key into the vector (160 bytes)
	std::copy(this->public_key, this->public_key + NUM_OF_BYTES_OF_PUBLIC_KEY, packed_payload.begin() + NUM_OF_BYTES_OF_USERNAME);

	return packed_payload;
}


ReconnectionPayload::ReconnectionPayload(const std::string& username) {
	// Copy the username with error handling
	errno_t result = strcpy_s(this->username, MAX_USERNAME_LENGTH, username.c_str());
	if (result != 0) {
		std::cerr << "Error copying username in ReconnectionPayload: source is too long!" << std::endl;
		this->username[0] = '\0'; // Ensure username is empty on error
	}

	// Initialize encrypted_aes_key as an empty string
	this->encrypted_aes_key[0] = '\0';
}
const string ReconnectionPayload::getEncryptedAESKey() const {
	string str_aes_key(this->encrypted_aes_key, this->encrypted_aes_key + sizeof(this->encrypted_aes_key));
	return str_aes_key;
}


string ReconnectionPayload::getUsername() const { return username; }

void ReconnectionPayload::setEncryptedAESKey(const char* encrypted_aes_key, const size_t key_length) {
	if (key_length <= ENCRYPTED_AES_KEY_LENGTH) {
		std::copy(encrypted_aes_key, encrypted_aes_key + key_length, this->encrypted_aes_key);
	}
	else {
		throw std::length_error("Key length exceeds ENCRYPTED_AES_KEY_LENGTH");
	}
}


Bytes ReconnectionPayload::pack_payload() const {
	Bytes packed_payload(RECONNECTION_PAYLOAD_SIZE, 0); // Initialize with zeroes the packed_payload

	// Get the actual length of the username string (up to 255)
	size_t username_length = std::strlen(this->username);

	// Copy the username into the vector
	std::copy(this->username, this->username + std::min(username_length, size_t(RECONNECTION_PAYLOAD_SIZE)), packed_payload.begin());

	return packed_payload;
}



ValidCrcPayload::ValidCrcPayload(const std::string& file_name) {
	memset(this->file_name, 0, sizeof(this->file_name));
	memcpy(this->file_name, file_name.c_str(), std::min(file_name.size(), static_cast<size_t>(MAX_FILE_NAME_LENGTH)));
}

string ValidCrcPayload::getFileName() const { return file_name; }

Bytes ValidCrcPayload::pack_payload() const {
	Bytes packed_payload(VALID_CRC_PAYLOAD_SIZE, 0); // Initialize with zeroes the packed_payload

	// Get the actual length of the file name string (up to VALID_CRC_PAYLOAD_SIZE)
	size_t file_name_length = std::strlen(this->file_name);

	// Copy the file_name into the vector
	std::copy(this->file_name, this->file_name + std::min(file_name_length, size_t(VALID_CRC_PAYLOAD_SIZE)), packed_payload.begin());
	return packed_payload;
}



InvalidCrcPayload::InvalidCrcPayload(const string& file_name) {
	memset(this->file_name, 0, sizeof(this->file_name));
	memcpy(this->file_name, file_name.c_str(), std::min(file_name.size(), static_cast<size_t>(MAX_FILE_NAME_LENGTH)));
}

string InvalidCrcPayload::getFileName() const { return file_name; }

Bytes InvalidCrcPayload::pack_payload() const {
	Bytes packed_payload(INVALID_CRC_PAYLOAD_SIZE, 0); // Initialize with zeroes the packed_payload

	// Get the actual length of the file name string (up to INVALID_CRC_PAYLOAD_SIZE)
	size_t file_name_length = std::strlen(this->file_name);

	// Copy the file_name into the vector
	std::copy(this->file_name, this->file_name + std::min(file_name_length, size_t(INVALID_CRC_PAYLOAD_SIZE)), packed_payload.begin());

	return packed_payload;
}



InvalidCrcDonePayload::InvalidCrcDonePayload(const string& file_name) {
	memset(this->file_name, 0, sizeof(this->file_name));
	memcpy(this->file_name, file_name.c_str(), std::min(file_name.size(), static_cast<size_t>(MAX_FILE_NAME_LENGTH)));
}

string InvalidCrcDonePayload::getFileName() const { return file_name; }

Bytes InvalidCrcDonePayload::pack_payload() const {
	Bytes packed_payload(INVALID_CRC_DONE_PAYLOAD_SIZE, 0); // Initialize with zeroes the packed_payload

	// Get the actual length of the file name string (up to INVALID_CRC_DONE_PAYLOAD_SIZE)
	size_t file_name_length = std::strlen(this->file_name);

	// Copy the file_name into the vector using std::copy
	std::copy(this->file_name, this->file_name + std::min(file_name_length, size_t(INVALID_CRC_DONE_PAYLOAD_SIZE)), packed_payload.begin());

	return packed_payload;
}




SendFilePayload::SendFilePayload(uint32_t content_size, uint32_t orig_file_size, uint16_t total_packets, const string& file_name, const string& encrypted_file_content)
	: content_size(content_size), orig_file_size(orig_file_size), packet_number(0), total_packets(total_packets), encrypted_file_content(encrypted_file_content),  cksum(0) {
	// Attempt to copy the file name
	memset(this->file_name, 0, sizeof(this->file_name));
	memcpy(this->file_name, file_name.c_str(), std::min(file_name.size(), static_cast<size_t>(MAX_FILE_NAME_LENGTH)));
}

// Setting the cksum to the given unsigned long variable
void SendFilePayload::setCksum(unsigned long cksum) {
	this->cksum = cksum;
}
// Getting the cksum received by the server
unsigned long SendFilePayload::getCksum() const {
	return this->cksum;
}

uint32_t SendFilePayload::get_content_size() const {
	return content_size;
}

uint32_t SendFilePayload::get_orig_file_size() const {
	return orig_file_size;
}

uint16_t SendFilePayload::get_packet_number() const {
	return packet_number;
}
void SendFilePayload::set_packet_number(const int packet_number) {
	this->packet_number =packet_number;
}

uint16_t SendFilePayload::get_total_packets() const {
	return total_packets;
}

string SendFilePayload::get_file_name() const { return file_name; }

const string& SendFilePayload::get_encrypted_file_content() const {
	return encrypted_file_content;
}

Bytes SendFilePayload::pack_payload(const Bytes message_content) const {
	Bytes packed_payload(SEND_FILE_PAYLOAD_SIZE, 0);

	// Iterator for filling the vector
	auto it = packed_payload.begin();

	// Convert and copy content_size (4 bytes) in little-endian
	uint32_t little_endian_content_size = htole32(this->content_size);

	it = std::copy(reinterpret_cast<const uint8_t*>(&little_endian_content_size),
		reinterpret_cast<const uint8_t*>(&little_endian_content_size) + sizeof(little_endian_content_size), it);
	
	// Convert and copy orig_file_size (4 bytes) in little-endian
	uint32_t little_endian_orig_file_size = htole32(this->orig_file_size);

	it = std::copy(reinterpret_cast<const uint8_t*>(&little_endian_orig_file_size),
		reinterpret_cast<const uint8_t*>(&little_endian_orig_file_size) + sizeof(little_endian_orig_file_size), it);

	// Convert and copy packet_number (2 bytes) in little-endian
	uint16_t little_endian_packet_number = htole16(this->packet_number);
	it = std::copy(reinterpret_cast<const uint8_t*>(&little_endian_packet_number),
		reinterpret_cast<const uint8_t*>(&little_endian_packet_number) + sizeof(little_endian_packet_number), it);

	// Convert and copy total_packets (2 bytes) in little-endian
	uint16_t little_endian_total_packets = htole16(this->total_packets);
	it = std::copy(reinterpret_cast<const uint8_t*>(&little_endian_total_packets),
		reinterpret_cast<const uint8_t*>(&little_endian_total_packets) + sizeof(little_endian_total_packets), it);

	// Copy the file_name (MAX_FILE_NAME_LENGTH bytes)
	it = std::copy(reinterpret_cast<const uint8_t*>(this->file_name),
		reinterpret_cast<const uint8_t*>(this->file_name) + MAX_FILE_NAME_LENGTH, it);

	it = std::copy(message_content.begin(), message_content.end(), it);

	// Ensure we don't overflow the packed_payload size 
	if (it > packed_payload.end()) {
		throw std::overflow_error("Packed payload size exceeded.");
	}

	return packed_payload;
}