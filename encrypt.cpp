#include <iostream>
#include <fstream>
#include <vector>

#include "include/aes.h"

int main(int argc, char* argv[]) {

    // Read contents
    std::cout << "reading file\n";
    std::ifstream pRead(argv[1], std::ios::binary);
    pRead.seekg(0, std::ios::end);
    std::streampos spSize = pRead.tellg();
    pRead.seekg(0);
    std::vector<unsigned char> data(spSize);
    pRead.read(reinterpret_cast<char*>(data.data()), spSize);
    pRead.close();

    // Padding
    int i = spSize;
    std::cout << i % 16 << "\n";
    while (i % 16 != 0) {
        data.push_back('0');
        std::cout << data[i] << "\n";
        i++;
    }
    std::cout << i % 16 << "\n";
    
    // AES encryption
    unsigned char* _key = (unsigned char*) "\x1A\xB2\xF8\xC5\x03\x7D\x9E\xA0\x6F\x84\x2D\xE7\x1B\x5C\x91\x6E";
    unsigned char* _iv = (unsigned char*) "\x8F\xD4\xE2\x70\xA9\xCB\xF5\x12\x63\x4E\x8A\xB7\x01\x9D\x3F\x56";
    std::vector<unsigned char> key(_key, _key + 16);
    std::vector<unsigned char> iv(_iv, _iv + 16);
    AES aes(AESKeyLength::AES_128);
    data = aes.EncryptCBC(data, key, iv);

    // Write back
    std::cout << "writing\n";
    std::ofstream pWrite("malware.shc", std::ios::binary);
    pWrite.write(reinterpret_cast<char*>(data.data()), spSize);
    pWrite.close();

    std::cout << "success\n";
    return 0;
}