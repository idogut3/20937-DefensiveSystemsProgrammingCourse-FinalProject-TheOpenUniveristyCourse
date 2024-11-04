#ifndef REQUEST_PAYLOADS_HPP
#define REQUEST_PAYLOADS_HPP
#include "request.hpp"
#include "utils.hpp"

class RegistrationPayload : public Payload {
protected:
    char username[MAX_USERNAME_LENGTH];
public:
    RegistrationPayload(const string& username);

    string getUsername() const;

    Bytes pack_payload() const;
};


class SendPublicKeyPayload : public Payload {
protected:
    char username[MAX_USERNAME_LENGTH];
    char public_key[PUBLIC_KEY_LENGTH];
    char encrypted_aes_key[ENCRYPTED_AES_KEY_LENGTH];

public:

    SendPublicKeyPayload(const string& username, const string& public_key);

    string getUsername() const;
    string getPublicKey() const;
    string getEncryptedAESKey() const;

    void setEncryptedAESKey(string encrypted_aes_key);

    Bytes pack_payload() const;
};



class ReconnectionPayload : public Payload {
private:
    char username[MAX_USERNAME_LENGTH];
    char encrypted_aes_key[ENCRYPTED_AES_KEY_LENGTH];

public:
    ReconnectionPayload(const string& username);

    string getUsername() const;
    const string getEncryptedAESKey() const;

    void setEncryptedAESKey(const char* encrypted_aes_key, const size_t key_length);

    Bytes pack_payload() const;
};



class ValidCrcPayload : public Payload {
protected:
    char file_name[MAX_FILE_NAME_LENGTH];

public:
    ValidCrcPayload(const string& file_name);

    string getFileName() const;

    Bytes pack_payload() const;
};




class InvalidCrcPayload : public Payload {
protected:
    char file_name[MAX_FILE_NAME_LENGTH];

public:
    InvalidCrcPayload(const string& file_name);
    string getFileName() const;

    Bytes pack_payload() const;
};



class InvalidCrcDonePayload : public Payload {
protected:
    char file_name[MAX_FILE_NAME_LENGTH];

public:
    InvalidCrcDonePayload(const string& file_name);
    string getFileName() const;

    Bytes pack_payload() const;
};



class SendFilePayload : public Payload {
protected:
    uint32_t content_size; // 4 bytes = 32 bits
    uint32_t orig_file_size; // 4 bytes = 32 bits
    uint16_t packet_number; // 2 bytes = 16 bits
    uint16_t total_packets; // 2 bytes = 16 bits
    char file_name[MAX_FILE_NAME_LENGTH];
    string encrypted_file_content;
    unsigned long cksum;
public:
    SendFilePayload(uint32_t content_size, uint32_t orig_file_size, uint16_t total_packets, const string& file_name, const string& encrypted_file_content);
    uint32_t get_content_size() const;
    uint32_t get_orig_file_size() const;
    uint16_t get_packet_number() const;
    uint16_t get_total_packets() const;
    void set_packet_number(const int packet_number);
    string get_file_name() const;
    const string& get_encrypted_file_content() const;
    void setCksum(unsigned long cksum);
    unsigned long getCksum() const;

    Bytes pack_payload(const Bytes message_content) const;
};



#endif