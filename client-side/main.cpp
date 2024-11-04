#include "request.hpp"
#include "requests.hpp"
#include "requests_payloads.hpp"
#include "utils.hpp"
#include "client.hpp"
#include "Base64Wrapper.hpp"
#include "RSAWrapper.hpp"
#include "cksum.hpp"

/** transferValidation
 *  Validates the parameters required for a file transfer.
 *
 * @param client A reference to a Client object that will be set up for the transfer.
 * @param ip_port A string representing the IP address and port in the format "ip:port".
 * @param name The username of the client initiating the transfer, must not be empty and within a defined length.
 * @param file_path The path to the file being transferred, must not be empty.
 * @return A boolean indicating whether the validation succeeded (true) or failed (false).
 *
 * The function performs the following checks:
 * 1. It ensures the ip_port string contains a colon (':') to separate the IP address and port.
 * 2. It checks that the username length is valid (greater than 0 and less than or equal to MAX_USERNAME_LENGTH).
 * 3. It verifies that the file_path is not empty.
 * 4. It extracts the IP address and port from the ip_port string and validates that the port is a valid integer.
 * 5. If all validations pass, it calls the setupClient method on the Client object to configure it for the transfer.
 */
static bool transferValidation(Client& client, string ip_port, string name, string file_path) {
	size_t colon_postion = ip_port.find(':');

	if (colon_postion == string::npos || name.length() > MAX_USERNAME_LENGTH || name.length() == 0 || file_path.length() == 0) {
		return false;
	}

	string ip = ip_port.substr(0, colon_postion);
	string port = ip_port.substr(colon_postion + 1);

	bool is_port_valid = is_integer(port);
	if (!is_port_valid) {
		return false;
	}

	client.setupClient(ip, port, name, file_path);

	return true;
}

/** createClient
 * Creates and initializes a Client object using configuration data from a file.
 *
 * @return A Client object that has been set up with values read from the 'transfer.info' file.
 *
 * This function performs the following steps:
 * 1. It constructs the path to the 'transfer.info' file.
 * 2. It opens the file and reads its contents line by line, expecting three specific pieces of information:
 *    - The first line contains the IP address and port.
 *    - The second line contains the client name.
 *    - The third line contains the file path for the transfer.
 * 3. It checks that exactly three lines are read from the file. If not, it throws an exception.
 * 4. It validates the extracted parameters using the transferValidation function.
 * 5. If all validations pass, it returns the configured Client object.
 * 6. If any errors occur during the file reading or validation, appropriate exceptions are thrown.
 */

static Client createClient() {
	string transfer_path = EXE_DIR_FILE_PATH("transfer.info");
	string line, ip_port, client_name, client_file_path;
	ifstream transfer_info_file(transfer_path);

	int lines = 1;
	Client client;

	if (!transfer_info_file.is_open()) {
		throw std::runtime_error("Error opening 'transfer.info' - exiting");
	}

	while (getline(transfer_info_file, line)) {
		switch (lines) {
		case 1:
			ip_port = line;
			break;
		case 2:
			client_name = line;
			break;
		case 3:
			client_file_path = line;
			break;
		default:
			break;
		}
		lines++;
	}

	if (lines != 4) {
		throw std::invalid_argument("Error: transfer.info contains too many lines / not enough lines");
	}

	if (!transferValidation(client, ip_port, client_name, client_file_path)) {
		throw std::invalid_argument("Error: transfer.info contains invalid data");
	}

	transfer_info_file.close();
	return client;

}

/** use_me_info_file
 * Reads configuration data from the 'me.info' file and updates the provided Client object.
 *
 * @param client A reference to a Client object that will be updated with the read data.
 * @return A string representing the private key extracted from the 'me.info' file.
 *
 * This function performs the following steps:
 * 1. Constructs the path to the 'me.info' file.
 * 2. Opens the file and reads its contents line by line, expecting specific information:
 *    - The first line contains the client name.
 *    - The second line contains the client ID (expected to be in a specific hexadecimal format).
 *    - The third line contains the private key, which may be spread across multiple lines.
 * 3. It checks that the read values meet specific criteria:
 *    - The client name must not be empty and must not exceed a predefined maximum length.
 *    - The client ID must have a fixed length defined by HEX_ID_LENGTH.
 *    - The private key must not be empty.
 * 4. If any validations fail, an exception is thrown.
 * 5. The client object is updated with the name and UUID derived from the client ID.
 * 6. Finally, the function closes the file and returns the private key.
 */

static string use_me_info_file(Client& client) {
	string me_info_path = EXE_DIR_FILE_PATH("me.info");
	string line, client_name, client_id, private_key;
	int lines = 1;
	ifstream info_file(me_info_path);

	if (!info_file.is_open()) {
		throw std::runtime_error("Error opening 'me.info' - exiting");
	}

	while (getline(info_file, line)) {
		switch (lines) {
		case 1:
			client_name = line;
			break;
		case 2:
			client_id = line;
			break;
		case 3:
			private_key = line;
			break;
		default:
			private_key += line;
			break;
		}
		lines++;
	}

	if (client_name.length() > MAX_USERNAME_LENGTH || client_name.length() == 0 || client_id.length() != HEX_ID_LENGTH || private_key.length() == 0) {
		throw std::invalid_argument("Error: me.info contains invalid data.");
	}

	UUID id = getUUIDFromString(client_id);
	client.setName(client_name);
	client.setUUID(id);

	info_file.close();
	return private_key;
}

/** save_me_info
 * Saves the client information to the 'me.info' file.
 *
 * @param name The name of the client to be saved.
 * @param uuid The UUID of the client, which will be converted to a string for storage.
 * @param private_key The private key of the client, which will be encoded in Base64 before saving.
 *
 * This function performs the following steps:
 * 1. Converts the UUID to a string format and removes any dashes ('-').
 * 2. Encodes the private key in Base64 to ensure safe storage.
 * 3. Constructs the path to the 'me.info' file where the information will be saved.
 * 4. Opens the file for writing. If the file cannot be opened, an exception is thrown.
 * 5. Writes the client name, UUID (without dashes), and Base64-encoded private key to the file, each on a new line.
 * 6. Closes the file after writing to ensure all data is properly saved.
 */

static void save_me_info(string name, UUID uuid, string private_key) {
	string my_uuid = uuids::to_string(uuid);
	my_uuid.erase(remove(my_uuid.begin(), my_uuid.end(), '-'), my_uuid.end()); // Remove '-' from the string
	string base64_private_key = Base64Wrapper::encode(private_key);

	string path_info = EXE_DIR_FILE_PATH("me.info");

	ofstream info_file(path_info);

	if (!info_file.is_open()) {
		throw std::runtime_error("Error opening the 'me.info' - exiting");
	}

	// Writing to info file
	info_file << name << "\n" << my_uuid << "\n" << base64_private_key << "\n";

	info_file.close();
}
/** save_priv_key_file
 * Saves the private key to a file after encoding it in Base64.
 *
 * @param private_key The private key to be saved, which will be encoded before storage.
 *
 * This function performs the following steps:
 * 1. Encodes the provided private key in Base64 format for secure storage.
 * 2. Constructs the path to the 'priv.key' file where the encoded private key will be saved.
 * 3. Opens the file for writing. If the file cannot be opened, an exception is thrown.
 * 4. Writes the Base64-encoded private key to the file, followed by a newline.
 * 5. Closes the file after writing to ensure all data is properly saved.
 */

static void save_priv_key_file(string private_key) {
	// Encode the private key to base64 and open files
	string base64_private_key = Base64Wrapper::encode(private_key);
	string path_key = EXE_DIR_FILE_PATH("priv.key");

	ofstream private_key_file(path_key);

	if (!private_key_file.is_open()) {
		throw std::runtime_error("Error opening the 'priv.key' file, aborting program.");
	}
	// Writing to priv.key file
	private_key_file << base64_private_key << "\n";
	private_key_file.close();
}

/** run_client
 * Executes the client operation, handling registration, reconnection,
 * and file transfer processes based on the client's state.
 *
 * @param sock A reference to a TCP socket for communication with the server.
 * @param client A reference to a Client object containing the client's information.
 *
 * This function performs the following steps:
 * 1. Checks if the 'me.info' file exists to determine if the client needs to register.
 *    - If the file does not exist, it sends a registration request to the server, generates
 *      an RSA key pair, saves the client information, and sends the public key.
 * 2. If the 'me.info' file exists:
 *    - Reads the client's information, sends a reconnection request to the server, and handles
 *      the responses accordingly.
 *    - If registered but not reconnected, it creates an RSA key pair, saves the client info,
 *      and sends the public key.
 *    - If the client is already registered and connected, it decrypts the AES key.
 * 3. After obtaining the AES key, it enters a loop to send the file:
 *    - Reads the file content, encrypts it using the AES key, and sends it to the server.
 *    - If the server responds with an incorrect checksum, it resends the CRC until a maximum
 *      number of attempts is reached.
 * 4. If the maximum attempts are reached, it notifies the server; otherwise, it sends a valid
 *    CRC request.
 */
static void run_client(tcp::socket& sock, Client& client) {
	int operation_success;
	string private_key, decrypted_aes_key;

	// if me.info does not exist, send registration request.
	if (!(std::filesystem::exists(EXE_DIR_FILE_PATH("me.info")))) {
		string client_name = client.getName();
		RequestHeader request_header(client.getUuid(), Codes::REGISTRATION_CODE, PayloadSize::REGISTRATION_PAYLOAD_SIZE);
		RegistrationPayload registration_payload(client_name);
		RegisterRequest register_request(request_header, registration_payload);
		operation_success = register_request.run(sock);

		if (operation_success == FAILURE) {
			FATAL_MESSAGE_RETURN("Register");
		}
		cout << "REGISTER REQUEST COMPLETED\n";
		client.setUUID(register_request.getHeader().getUUID());
		// create rsa pair, save fields data into me.info and prev.key files, and send a sendingpublickey request.
		RSAPrivateWrapper rsa_wrapper;

		string public_key = rsa_wrapper.getPublicKey();
		private_key = rsa_wrapper.getPrivateKey();

		// saving files as required for future 
		save_me_info(client.getName(), client.getUuid(), private_key);
		save_priv_key_file(private_key);

		RequestHeader send_public_key_request_header(client.getUuid(), Codes::SENDING_PUBLIC_KEY_CODE, PayloadSize::SENDING_PUBLIC_KEY_PAYLOAD_SIZE);
		string username = client.getName();
		SendPublicKeyPayload send_public_key_request_payload(username, public_key);

		SendPublicKeyRequest send_public_key_request(send_public_key_request_header, send_public_key_request_payload);
		
		operation_success = send_public_key_request.run(sock);

		if (operation_success == FAILURE) {
			FATAL_MESSAGE_RETURN("sending public key");
		}
		cout << "SEND PUBLIC KEY COMPLETED\n";

		// Get the encrypted aes key and decrypt it.
		string encrypted_aes_key = send_public_key_request.getEncryptedAESKey();
		decrypted_aes_key = rsa_wrapper.decrypt(encrypted_aes_key);
	}

	else {
		// if me.info does exist, read id and send reconnection request.
		// read the fields from the client.
		string key_base64 = use_me_info_file(client);

		// send reconnection request to the server
		RequestHeader reconnect_request_header(client.getUuid(), Codes::RECONNECTION_CODE, PayloadSize::RECONNECTION_PAYLOAD_SIZE);

		string username = client.getName();
		ReconnectionPayload reconnect_request_payload(username);

		ReconnectRequest reconnect_request(reconnect_request_header, reconnect_request_payload);
		operation_success = reconnect_request.run(sock);

		if (operation_success == FAILURE) {
			FATAL_MESSAGE_RETURN("Reconnect");
		}
		else if (operation_success == REGISTERED_NOT_RECONNECTED) {
			client.setUUID(reconnect_request.getHeader().getUUID());
			// create rsa pair, save fields data into me.info and prev.key files, and send a sendingpublickey request.
			RSAPrivateWrapper rsa_wrapper;

			string public_key = rsa_wrapper.getPublicKey();
			private_key = rsa_wrapper.getPrivateKey();

			// saving files as required for future 
			save_me_info(client.getName(), client.getUuid(), private_key);
			save_priv_key_file(private_key);

			RequestHeader send_public_key_request_header(client.getUuid(), Codes::SENDING_PUBLIC_KEY_CODE, PayloadSize::SENDING_PUBLIC_KEY_PAYLOAD_SIZE);
			string username = client.getName();
			SendPublicKeyPayload send_public_key_request_payload(username, public_key);

			SendPublicKeyRequest send_public_key_request(send_public_key_request_header, send_public_key_request_payload);

			operation_success = send_public_key_request.run(sock);

			if (operation_success == FAILURE) {
				FATAL_MESSAGE_RETURN("sending public key");
			}
			cout << "SEND PUBLIC KEY COMPLETED\n";

			// Get the encrypted aes key and decrypt it.
			string encrypted_aes_key = send_public_key_request.getEncryptedAESKey();
			decrypted_aes_key = rsa_wrapper.decrypt(encrypted_aes_key);
		}
		else{
			// decode the private key and create the decryptor
			private_key = Base64Wrapper::decode(key_base64);
			RSAPrivateWrapper rsa_wrapper(private_key);

			// get the encrypted aes key and decrypt it
			string encrypted_aes_key = reconnect_request.getPayload()->getEncryptedAESKey();
			decrypted_aes_key = rsa_wrapper.decrypt(encrypted_aes_key);
		}
		cout << "RECONNECT REQUEST COMPLETED\n";
	}

	AESWrapper aes_key_wrapper(reinterpret_cast<const unsigned char*>(decrypted_aes_key.c_str()), static_cast<unsigned int>(decrypted_aes_key.size()));
	int times_crc_sent = 0;

	while (times_crc_sent != MAX_REQUEST_FAILS) {
		// get the file's content, save the encrypted content and save the sizes of both.
		std::string content = fileToString(client.getFilePath());
		std::string file_encrypted_content = aes_key_wrapper.encrypt(content.c_str(), static_cast<unsigned int>(content.length()));
		uint32_t content_size = file_encrypted_content.length();
		uint32_t orig_file_size = content.length();

		// save the total packets and send the sending file request to the server.
		uint16_t total_packs = TOTAL_PACKETS(content_size);
		RequestHeader send_file_request_header(client.getUuid(), Codes::SENDING_FILE_CODE, PayloadSize::SEND_FILE_PAYLOAD_SIZE);

		string file_name = client.getFilePath();
		SendFilePayload send_file_request_payload(content_size, orig_file_size, total_packs , file_name, file_encrypted_content);

		SendFileRequest send_file_request(send_file_request_header, send_file_request_payload);

		operation_success = send_file_request.run(sock);
		// if the sending file request did not succeed, add 1 to sending file error counter and continue the loop.
		if (operation_success == FAILURE) {
			FATAL_MESSAGE_RETURN("SEND FILE");
		}
		cout << "SEND FILE REQUEST COMPLETED \n";
		
		// get the cksum the server responded with.
		unsigned long response_cksum = send_file_request.getPayload()->getCksum();
		cout << "RESPONSE CRC " << response_cksum << "\n";
		if (response_cksum == memcrc(content.c_str(), orig_file_size)) {
			cout << "Correct checksum ! \n";
			break;
		}

		// if the crc given by the server is incorrect, send sending crc again request - 901.
		RequestHeader invalid_crc_request_header(client.getUuid(), Codes::SENDING_CRC_AGAIN_CODE, PayloadSize::INVALID_CRC_PAYLOAD_SIZE);
		InvalidCrcPayload invalid_crc_request_payload(client.getFilePath());
		InvalidCrcRequest invalid_crc_request(invalid_crc_request_header, invalid_crc_request_payload);

		invalid_crc_request.run(sock);
		// if the sending crc request did not succeed, add 1 to times crc sent counter.
		times_crc_sent++;
	}

	if (times_crc_sent == MAX_REQUEST_FAILS) {
		RequestHeader invalid_crc_done_request_header(client.getUuid(), Codes::INVALID_CRC_DONE_CODE, PayloadSize::INVALID_CRC_DONE_PAYLOAD_SIZE);
		InvalidCrcDonePayload invalid_crc_done_request_payload(client.getFilePath());
		InvalidCrcDoneRequest invalid_crc_done_request(invalid_crc_done_request_header, invalid_crc_done_request_payload);

		invalid_crc_done_request.run(sock);
	}
	else {
		cout << "SENT CRC VALID REQUEST \n";
		RequestHeader valid_crc_request_header(client.getUuid(), Codes::VALID_CRC_CODE, PayloadSize::VALID_CRC_PAYLOAD_SIZE);
		ValidCrcPayload valid_crc_request_payload(client.getFilePath());
		ValidCrcRequest valid_crc_request(valid_crc_request_header, valid_crc_request_payload);
		operation_success = valid_crc_request.run(sock);
		if (operation_success == FAILURE) {
			FATAL_MESSAGE_RETURN("VALID CRC");
		}
	}
}


/** main
 * Main entry point for the client application.
 *
 * This function performs the following steps:
 * 1. Attempts to create a Client object by reading from the configuration files.
 * 2. Initializes the Boost.Asio IO context and TCP socket for network communication.
 * 3. Resolves the server address and connects the socket to the server.
 * 4. Calls the `run_client` function to handle the main client operations.
 * 5. Catches any exceptions that may occur during the process and outputs the error message.
 *
 * @return An integer representing the exit status of the application (0 for success).
 */

int main()
{
	try {
		Client client = createClient();

		boost::asio::io_context io_context;
		tcp::socket sock(io_context);
		tcp::resolver resolver(io_context);
		boost::asio::connect(sock, resolver.resolve(client.getAddress(), client.getPort()));

		run_client(sock, client);
	}
	catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
	}
}

