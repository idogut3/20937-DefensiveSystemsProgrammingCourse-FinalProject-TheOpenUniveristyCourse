#include "request.hpp"
#include "utils.hpp"

RequestHeader::RequestHeader(UUID user_id, uint16_t request_code, uint32_t request_payload_size)
	: uuid(user_id), version(VERSION), code(request_code), payload_size(request_payload_size) {}

UUID RequestHeader::getUUID() const {
	return this->uuid;
}
uint8_t RequestHeader::getVersion() const {
	return this->version;
}
uint16_t RequestHeader::getCode() const {
	return this->code;
}
uint32_t RequestHeader::getPayloadSize() const {
	return this->payload_size;
}

void RequestHeader::setUUIDFromRawBytes(const Bytes& uuid_bytes) {
	// Assuming response_payload is already validated to be exactly 16 bytes
	std::copy(uuid_bytes.begin(), uuid_bytes.end(), this->uuid.begin());
}

RequestHeader Request::getHeader() const {
	return this->header;
}
RequestHeader& Request::getHeaderReference() {
	return this->header;
}

/** RequestHeader::pack_header()
 * Packs the request header into a byte array.
 *
 * This function constructs a byte array representation of the request header,
 * including the UUID, version, response code, and payload size. The values
 * are stored in little-endian format to ensure proper serialization for network
 * transmission.
 *
 * @return A vector of bytes representing the packed header.
 */

Bytes RequestHeader::pack_header() const {
	Bytes packed_header(REQUEST_HEADER_SIZE);

	// Saving the numeric type in little endian order
	uint16_t code_in_little_endian = native_to_little(this->code);
	uint32_t payload_size_in_little_endian = native_to_little(this->payload_size);

	// Saving the bytes in little endian order as a byte array.
	uint8_t* code_in_little_endian_ptr = reinterpret_cast<uint8_t*>(&code_in_little_endian);
	uint8_t* payload_size_in_little_endian_ptr = reinterpret_cast<uint8_t*>(&payload_size_in_little_endian);

	// Adding fields to the vector
	size_t position = 0;

	std::copy(uuid.begin(), uuid.end(), packed_header.begin()); // Copying the uuid to the beginning of packed_header
	position += sizeof(uuid); // Move the position forward by the size of UUID

	packed_header[position] = version; // after the uuid we insert the version
	position += sizeof(version); // Move the position forward by the size of version

	std::copy(code_in_little_endian_ptr, code_in_little_endian_ptr + sizeof(code_in_little_endian), packed_header.begin() + position);
	position += sizeof(code); // Move the position forward by the size of code

	std::copy(payload_size_in_little_endian_ptr, payload_size_in_little_endian_ptr + sizeof(payload_size_in_little_endian), packed_header.begin() + position);

	return packed_header;
}

Request::Request(RequestHeader request_header)
	: header(request_header) {}

