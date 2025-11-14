#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>

// Подключаем заголовки Crypto++
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;

// Функция для вычисления хэша файла с использованием выбранного алгоритма
string CalculateFileHash(const string& filename, const string& algorithm) {
    string digest;
    
    try {
        if (algorithm == "sha1") {
            SHA1 hash;
            FileSource(filename.c_str(), true, 
                      new HashFilter(hash,
                      new HexEncoder(
                      new StringSink(digest))));
        }
        else if (algorithm == "sha256") {
            SHA256 hash;
            FileSource(filename.c_str(), true, 
                      new HashFilter(hash,
                      new HexEncoder(
                      new StringSink(digest))));
        }
        else if (algorithm == "sha3_256") {
            SHA3_256 hash;
            FileSource(filename.c_str(), true, 
                      new HashFilter(hash,
                      new HexEncoder(
                      new StringSink(digest))));
        }
        else if (algorithm == "md5") {
            MD5 hash;
            FileSource(filename.c_str(), true, 
                      new HashFilter(hash,
                      new HexEncoder(
                      new StringSink(digest))));
        }
        else {
            // По умолчанию используем SHA256
            SHA256 hash;
            FileSource(filename.c_str(), true, 
                      new HashFilter(hash,
                      new HexEncoder(
                      new StringSink(digest))));
        }
    }
    catch(const exception& e) {
        cerr << "Ошибка при вычислении хэша: " << e.what() << endl;
        return "";
    }
    
    return digest;
}

// Функция для отображения справки
void PrintHelp() {
    cout << "Использование: hash_program <файл> [алгоритм]" << endl;
    cout << "Поддерживаемые алгоритмы:" << endl;
    cout << "  sha1     - SHA-1 (160 бит)" << endl;
    cout << "  sha256   - SHA-256 (256 бит)" << endl;
    cout << "  sha3_256 - SHA3-256 (256 бит)" << endl;
    cout << "  md5      - MD5 (128 бит)" << endl;
    cout << endl;
    cout << "Примеры:" << endl;
    cout << "  hash_program document.txt" << endl;
    cout << "  hash_program image.jpg sha256" << endl;
    cout << "  hash_program data.bin md5" << endl;
}

int main(int argc, char* argv[]) {
    // Проверка количества аргументов
    if (argc < 2 || argc > 3) {
        PrintHelp();
        return 1;
    }
    
    string filename = argv[1];
    string algorithm = "sha256"; // Алгоритм по умолчанию
    
    // Если указан алгоритм
    if (argc == 3) {
        algorithm = argv[2];
    }
    
    // Проверяем существование файла
    ifstream file(filename);
    if (!file.good()) {
        cerr << "Ошибка: файл '" << filename << "' не существует или недоступен" << endl;
        return 1;
    }
    file.close();
    
    cout << "Вычисление хэша..." << endl;
    cout << "Файл: " << filename << endl;
    cout << "Алгоритм: " << algorithm << endl;
    
    string hash = CalculateFileHash(filename, algorithm);
    
    if (!hash.empty()) {
        cout << "Хэш: " << hash << endl;
        cout << "Длина хэша: " << hash.length() << " символов (" 
             << (hash.length() / 2) << " байт)" << endl;
    } else {
        cerr << "Не удалось вычислить хэш" << endl;
        return 1;
    }
    
    return 0;
}