#include "utils.hpp"

/**
 * Overloads the + operator to concatenate two Bytes objects.
 *
 * @param first The first Bytes object to concatenate.
 * @param second The second Bytes object to concatenate.
 * @return A new Bytes object that is the result of the concatenation.
 */

Bytes operator+(const Bytes& first, const Bytes& second) {
	Bytes result;
	result.reserve(first.size() + second.size());
	result.insert(result.end(), first.begin(), first.end());  // Insert first at the end
	result.insert(result.end(), second.begin(), second.end());  // Append second at the end
	return result;
}

/**
 * Overloads the << operator to print a Bytes object.
 *
 * @param os The output stream to which the Bytes object will be printed.
 * @param bytes The Bytes object to print.
 * @return The output stream for chaining.
 */
std::ostream& operator<<(std::ostream& os, const Bytes& bytes) {
	for (const auto& byte : bytes) {
		os << static_cast<int>(byte) << " "; // Cast to int for proper display
	}
	return os; // Return the stream to allow chaining
}

/** getUUIDFromString
 * Generates a UUID from a given string representation of a client ID.
 *
 * @param client_id The string representation of the client ID.
 * @return A UUID generated from the client ID string.
 */
UUID getUUIDFromString(string client_id)
{
	UUIDGenerator uuid_generator;  // Use the alias for boost::uuids::string_generator
	return uuid_generator(client_id);  // Generate and return a UUID from the string
}
/** is_integer
 * Checks if a given string represents a valid integer.
 *
 * @param num The string to check.
 * @return true if the string represents a valid integer; false otherwise.
 */
bool is_integer(const std::string& num) {
	if (num.empty()) {
		return false; // Empty string is not a valid integer
	}

	std::size_t start = 0;

	// Check for a leading sign ('+' or '-')
	if (num[0] == '+' || num[0] == '-') {
		if (num.length() == 1) {
			return false;  // A single '+' or '-' is not a valid integer
		}
		start = 1; // Start checking digits after the sign
	}

	// Check if all remaining characters are digits
	for (std::size_t i = start; i < num.length(); ++i) {
		if (!std::isdigit(num[i])) {
			return false;  // Non-digit character found none 0-9 char
		}
	}

	return true;  // All characters are digits (or valid sign)
}
/** extractCodeFromResponseHeader
 * Extracts the response code from the given header.
 *
 * This function takes a header in the form of a byte array and extracts
 * a 16-bit response code from the specified bytes within the header. It
 * checks the system's endianness and reverses the byte order if the
 * native order is little-endian.
 *
 * @param header A byte array representing the response header.
 *               Must contain at least 3 bytes.
 * @return uint16_t The extracted response code.
 * @throws std::invalid_argument if the header is too small to extract the code.
 */
uint16_t extractCodeFromResponseHeader(const Bytes& header) {
	uint8_t high = header[1], low = header[2];
	uint16_t combined = (static_cast<uint16_t>(high) << 8) | low;

	if (boost::endian::order::native == boost::endian::order::little) {
		return boost::endian::endian_reverse(combined);
	}
	cout << combined << "\n";
	return combined;
}
/** extractPayloadSizeFromResponseHeader
 * Extracts the payload size from the given response header.
 *
 * This function takes a byte array representing the response header and
 * extracts a 32-bit payload size from specific bytes within the header.
 * It checks the system's endianness and reverses the byte order if the
 * native order is little-endian.
 *
 * @param header A byte array representing the response header.
 *               Must contain at least 7 bytes.
 * @return uint32_t The extracted payload size.
 * @throws std::invalid_argument if the header is too small to extract the payload size.
 */
uint32_t extractPayloadSizeFromResponseHeader(const Bytes& header) {
	uint8_t first = header[3], second = header[4];
	uint8_t third = header[5], forth = header[6];

	uint32_t combined = (static_cast<uint32_t>(first) << 24) |
		(static_cast<uint32_t>(second) << 16) |
		(static_cast<uint32_t>(third) << 8) |
		(static_cast<uint32_t>(forth));

	if (boost::endian::order::native == boost::endian::order::little) {
		return boost::endian::endian_reverse(combined);
	}

	return combined;
}
/** extractPayloadContentSize
 * Extracts the payload content size from the given response payload.
 *
 * This function extracts a 32-bit content size from a byte array representing
 * the response payload. The size is located at specific indices in the payload,
 * starting from index 16. The function combines the four bytes into a single
 * 32-bit value.
 *
 * @param response_payload A byte array representing the response payload.
 *                         Must contain at least 20 bytes.
 * @return uint32_t The extracted content size.
 * @throws std::out_of_range if the response_payload is too small to extract the content size.
 */

uint32_t extractPayloadContentSize(Bytes response_payload) {
	// Extract the 4 bytes starting from index 16 and convert to uint32_t
	uint32_t content_size = (static_cast<uint32_t>(response_payload[16])) |
		(static_cast<uint32_t>(response_payload[17]) << 8) |
		(static_cast<uint32_t>(response_payload[18]) << 16) |
		(static_cast<uint32_t>(response_payload[19]) << 24);
	return content_size;
}
/** extractSendFileResponseFileName
 * Extracts the file name from the send file response payload.
 *
 * This function extracts the file name from the response payload, which starts
 * at index 20 and can be up to a maximum defined length (MAX_FILE_NAME_LENGTH).
 * It also removes any null terminators that may be present at the end of the
 * extracted string.
 *
 * @param response_payload A byte array representing the response payload.
 *                         Must contain sufficient data to extract the file name.
 * @return std::string The extracted file name.
 * @throws std::out_of_range if the response_payload is too small to extract the file name.
 */

string extractSendFileResponseFileName(Bytes response_payload) {
	// The file name starts at index 20 and can be up to MAX_FILE_NAME_LENGTH bytes long
	size_t file_name_start = 20;
	size_t file_name_length = std::min(static_cast<size_t>(MAX_FILE_NAME_LENGTH), response_payload.size() - file_name_start);

	// Create a string from the response payload data starting at index 20
	std::string file_name(reinterpret_cast<const char*>(response_payload.data() + file_name_start), file_name_length);

	// Remove any null terminators from the end of the string
	file_name.erase(std::find(file_name.begin(), file_name.end(), '\0'), file_name.end());

	return file_name;
}
/** extractSendFileResponseCksum
 * Extracts the checksum from the send file response payload.
 *
 * This function extracts a 32-bit checksum value from the response payload,
 * which is located at a fixed position (index 275). It combines four bytes
 * into a single 32-bit value and accounts for endianness based on the native
 * order of the system.
 *
 * @param response_payload A byte array representing the response payload.
 *                         Must contain sufficient data to extract the checksum.
 * @return unsigned long The extracted checksum as a 32-bit unsigned long.
 * @throws std::out_of_range if the response_payload is too small to extract the checksum.
 */

unsigned long extractSendFileResponseCksum(Bytes response_payload) {
	size_t start = 275;

	uint8_t first = response_payload[start], second = response_payload[start + 1];
	uint8_t third = response_payload[start + 2], forth = response_payload[start + 3];

	uint32_t combined = (static_cast<uint32_t>(first) << 24) |
		(static_cast<uint32_t>(second) << 16) |
		(static_cast<uint32_t>(third) << 8) |
		(static_cast<uint32_t>(forth));

	
	if (boost::endian::order::native == boost::endian::order::little) {
		return boost::endian::endian_reverse(combined);
	}

	return combined;
}



/** are_uuids_equal
 * Compares two UUIDs for equality.
 *
 * This function checks if the provided byte array (first) matches the
 * specified UUID (second). Both representations should be of the same size
 * (16 bytes).
 *
 * @param first A byte array representing the first UUID.
 * @param second A UUID object representing the second UUID.
 * @return true if the UUIDs are equal, false otherwise.
 */
bool are_uuids_equal(const Bytes first, const UUID second) {
	for (int i = 0; i < first.size(); i++) {
		if (first[i] != second.data[i]) {
			return false;
		}
	}
	return true;
}

/** htole32
 * Converts a 32-bit integer from host to little-endian format.
 *
 * This function takes a 32-bit unsigned integer in host byte order and converts it
 * to little-endian byte order using Boost's endian support.
 *
 * @param x The 32-bit unsigned integer to convert.
 * @return The converted 32-bit unsigned integer in little-endian format.
 */

uint32_t htole32(uint32_t x) {
	return boost::endian::native_to_little(x);
}
/** htole16
 * Converts a 16-bit integer from host to little-endian format.
 *
 * This function takes a 16-bit unsigned integer in host byte order and converts it
 * to little-endian byte order using Boost's endian support.
 *
 * @param x The 16-bit unsigned integer to convert.
 * @return The converted 16-bit unsigned integer in little-endian format.
 */

uint16_t htole16(uint16_t x) {
	return boost::endian::native_to_little(x);
}

/** fileToString
 * Reads the contents of a file into a string.
 *
 * This function constructs the full file path using a predefined macro and attempts to
 * read the entire content of the specified file into a string. It handles both
 * binary files and checks for the file's existence before attempting to read.
 *
 * @param file_path The relative path of the file to read.
 * @return A string containing the contents of the file. If the file does not exist
 *         or cannot be opened, an empty string is returned.
 */

string fileToString(std::string file_path) {
	string full_path = EXE_DIR_FILE_PATH(file_path);
	std::string file_as_a_string;

	if (std::filesystem::exists(full_path)) {
		std::ifstream file(full_path,std::ios::binary);  // Open the file
		if (file) {
			std::ostringstream ss;
			ss << file.rdbuf();  // Read the file into a string stream
			file_as_a_string = ss.str();  // Convert the string stream into a string
			
		}
		else {
			std::cerr << "Error: Unable to open file.\n";
		}

	}
	return file_as_a_string;
}
/** stringToBytes
 * Converts a string to a vector of bytes.
 *
 * This function takes a string input and converts each character into its corresponding
 * byte value, storing the result in a vector. It reserves space in the vector to
 * optimize performance during the conversion.
 *
 * @param input The string to be converted to bytes.
 * @return A vector of bytes representing the input string, where each byte corresponds
 *         to a character from the input string.
 */
Bytes stringToBytes(const string& input) {
	// Create a vector to hold the bytes
	Bytes byteArray;

	// Reserve space to optimize performance (optional)
	byteArray.reserve(input.size());

	// Convert each character to its corresponding byte value
	for (char c : input) {
		byteArray.push_back(static_cast<uint8_t>(c)); // Cast to uint8_t
	}

	return byteArray;  // Return the vector of bytes
}