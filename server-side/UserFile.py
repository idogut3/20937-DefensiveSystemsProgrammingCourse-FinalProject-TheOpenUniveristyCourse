from CryptoUtils import decrypt_file_with_aes_key
from utils import calculate_checksum_value


class UserFile:
    MAX_PACK_LENGTH = 1024

    def __init__(self, file_path):
        self._file_name: str | None = None
        self._total_packets: int | None = None
        self._packets: dict[int, bytes] = {}
        self._crc: int | None = None
        self._encrypted_content_size: int | None = None
        self._file_path = file_path

    def set_file_name(self, file_name: str) -> None:
        self._file_name = file_name

    def set_total_packets(self, tot_packets: int) -> None:
        self._total_packets = tot_packets

    def set_crc(self, crc: int) -> None:
        self._crc = crc

    def set_encrypted_content_size(self, encrypted_content_size: int) -> None:
        self._encrypted_content_size = encrypted_content_size

    def get_file_name(self) -> str:
        return self._file_name

    def get_total_packets(self):
        return self._total_packets

    def get_packets(self) -> dict[int, bytes]:
        return self._packets

    def get_crc(self) -> int:
        return self._crc

    def get_encrypted_content_size(self) -> int:
        return self._encrypted_content_size

    # This method clears the packets dictionary in case the client sends from the beginning
    def clear_dict(self) -> None:
        self._packets.clear()

    # This method adds the data given using the provided packet number as a key.
    def add_packet_data(self, packet_number: int, data: bytes) -> None:
        self._packets[packet_number] = data
        print("added packet data, packet num = ", packet_number)

    def received_entire_file(self) -> bool:
        print("len self packs", len(self._packets), " , total packs =", self._total_packets)
        return len(self._packets) == self._total_packets

    def decrypt_and_write_file_data_to_memory(self, aes_key) -> None:
        """
           Decrypts the encrypted file data stored in packets and writes the decrypted content to the specified file.

           Args:
               aes_key (bytes): The AES key used for decryption.

           Raises:
               ValueError: If the total packets are not set or if any packet data is missing.
        """
        if self.get_total_packets() is None:
            raise ValueError("Total packets not set. Cannot write to file.")
        PACKET_SIZE = 1024
        # Collect all packet data into a bytearray
        combined_data = bytearray()
        for packet_number in range(self.get_total_packets()):
            if packet_number in self.get_packets():
                data = self.get_packets()[packet_number]
                amt_to_write = min(PACKET_SIZE, self._encrypted_content_size - packet_number * PACKET_SIZE)
                stripped_data = data[:amt_to_write]
                combined_data.extend(stripped_data)
            else:
                raise ValueError(f"Missing packet data for packet number: {packet_number}")

        # Decrypt the combined data
        decrypted_data = decrypt_file_with_aes_key(encrypted_file=combined_data, aes_key=aes_key)


        # Write the decrypted data back to the file in binary format
        with open(self._file_path, 'wb') as file:
            file.write(decrypted_data)

        # Calculate checksum and set values
        crc = calculate_checksum_value(decrypted_data)
        self.set_crc(crc)


