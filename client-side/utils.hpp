#ifndef UTILS_HPP
#define UTILS_HPP

#include <fstream>
#include <iostream>
#include <string>
#include <string.h>    
#include <vector>
#include <filesystem>

#include <boost/asio.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
//#include <boost/uuid/nil.hpp>
#include <boost/uuid/nil_generator.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/uuid/string_generator.hpp>

#include "AESWrapper.hpp"
#include "Base64Wrapper.hpp"
#include "RSAWrapper.hpp"

#include "codes.hpp"
#include "payloads_sizes.hpp"


namespace uuids = boost::uuids;

using std::cout;
using std::cin;

using std::vector;
using std::string;
using std::ifstream;
using std::ofstream;
using std::fstream;

using boost::asio::ip::tcp;
using UUID = boost::uuids::uuid;
const UUID NIL_UUID = boost::uuids::nil_uuid();
using UUIDGenerator = boost::uuids::string_generator;
using boost::uuids::to_string;
using boost::endian::little_to_native;
using boost::endian::native_to_little;

using Byte = uint8_t;
using Bytes = std::vector<Byte>;

constexpr auto VERSION = 3;
constexpr auto MAX_USERNAME_LENGTH = 255;
constexpr auto PUBLIC_KEY_LENGTH = 160;
constexpr auto ENCRYPTED_AES_KEY_LENGTH = 128;
constexpr auto MAX_FILE_NAME_LENGTH = 255;
constexpr auto REQUEST_HEADER_SIZE = 23;
constexpr auto RESPONSE_HEADER_SIZE = 7;
constexpr auto HEX_ID_LENGTH = 32;
constexpr size_t CONTENT_SIZE_PER_PACKET = 1024;
constexpr auto MAX_REQUEST_FAILS = 3;
constexpr size_t UUID_SIZE = 16;

constexpr size_t SEND_FILE_REQUEST_HEADER_EXTRAS_SIZE = 267;


constexpr int SUCCESS = 0;
constexpr int FAILURE = 1;
constexpr int REGISTERED_NOT_RECONNECTED = 2;


const std::string EXE_DIR = "client.cpp\\..\\..\\x64\\debug"; //Todo: change later cuz folders
#define EXE_DIR_FILE_PATH(file_name) (EXE_DIR + "\\" + file_name)
#define FATAL_MESSAGE_RETURN(type) \
	std::cerr << "Fatal: " << type << " request failed.\n"; \
	return;

#define TOTAL_PACKETS(content_size) \
	((content_size % CONTENT_SIZE_PER_PACKET) ? (content_size/CONTENT_SIZE_PER_PACKET + 1) : content_size/CONTENT_SIZE_PER_PACKET)



Bytes operator+(const Bytes& first, const Bytes& second);
std::ostream& operator<<(std::ostream & os, const Bytes & bytes);
UUID getUUIDFromString(string client_id);
bool is_integer(const std::string& num);
uint16_t extractCodeFromResponseHeader(const Bytes& header);
uint32_t extractPayloadSizeFromResponseHeader(const Bytes& header);
uint32_t extractPayloadContentSize(Bytes response_payload);
string extractSendFileResponseFileName(Bytes response_payload);
unsigned long extractSendFileResponseCksum(Bytes response_payload);

// This method receives two uuids, one as a vector<uint8_s> (Bytes) and one as a boost::uuids::uuid type, and checks if they're identical.
bool are_uuids_equal(const Bytes first, const UUID second);

uint32_t htole32(uint32_t x);
uint16_t htole16(uint16_t x);

string fileToString(std::string file_path);
Bytes stringToBytes(const string & input);



#endif