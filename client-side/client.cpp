#include "client.hpp"
#include "utils.hpp"

Client::Client() {
	this->address = "";
	this->port = "";
	this->name = "";
	this->file_path = "";
	this->uuid = NIL_UUID;
}

void Client::setAddress(string address) {
	this->address = address;
}
void Client::setPort(string port) {
	this->port = port;
}
void Client::setName(string name) {
	this->name = name;
}
void Client::setFilePath(string file_path) {
	this->file_path = file_path;
}
void Client::setUUID(UUID uuid) {
	this->uuid = uuid;
}

string Client::getAddress() const {
	return this->address;
}

string Client::getPort() const {
	return this->port;
}

string Client::getName() {
	return this->name;
}

string Client::getFilePath() const {
	return this->file_path;
}

UUID Client::getUuid() const {
	return this->uuid;
}

void Client::setupClient(const string& ip, const string& port, const string& name, const string& filePath) {
	this->setAddress(ip);
	this->setPort(port);
	this->setName(name);
	this->setFilePath(filePath);
}