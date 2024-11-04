#ifndef REQUEST_HPP
#define REQUEST_HPP
#include "utils.hpp"

class RequestHeader {
protected:
	UUID uuid;
	uint8_t version;
	uint16_t code;
	uint32_t payload_size;

public:
	RequestHeader(UUID uuid, uint16_t code, uint32_t payload_size);
	UUID getUUID() const;

	uint8_t getVersion() const;
	uint16_t getCode() const;
	uint32_t getPayloadSize() const;

	void setUUIDFromRawBytes(const Bytes& uuid_bytes);

	Bytes pack_header() const;
};

class Payload {
public:
//	virtual Bytes pack_payload() const = 0;
	virtual ~Payload() = default; // Virtual destructor
};

class Request {
protected:
	RequestHeader header;

public:
	Request(RequestHeader header);

	RequestHeader getHeader() const;
	RequestHeader& getHeaderReference();

	// Pure virtual function that returns a pointer to Payload to avoid object slicing
	virtual const Payload* getPayload() const = 0;

	// Pure Virtual function, each request derived class will implement this function.
//	virtual Bytes pack_request() const = 0;
	virtual int run(tcp::socket& sock) = 0;
};

#endif 