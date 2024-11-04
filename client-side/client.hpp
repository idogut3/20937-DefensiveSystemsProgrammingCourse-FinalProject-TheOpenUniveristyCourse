#ifndef CLIENT_H
#define CLIENT_H

#include "utils.hpp"


class Client {
	string address;
	string port;
	string name;
	string file_path;
	UUID uuid;

public:
	Client();
	void setAddress(string address);
	void setPort(string port);
	void setName(string name);
	void setFilePath(string file_path);
	void setUUID(UUID uuid);

	string getAddress() const;
	string getPort() const;
	string getName();
	string getFilePath() const;
	UUID getUuid() const;
	void setupClient(const string& ip, const string& port, const string& name, const string& filePath);
};

#endif