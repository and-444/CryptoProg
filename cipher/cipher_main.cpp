#include <iostream>
#include <fstream>
#include <string>
#include <vector>

// Подключаем заголовки Crypto++
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

using namespace std;
using namespace CryptoPP;

// Функция для вывода справки
void PrintHelp() {
    cout << "Программа шифрования/дешифрования файлов" << endl;
    cout << "Использование:" << endl;
    cout << "  Шифрование: cipher_program -e <входной файл> <выходной файл>" << endl;
    cout << "  Дешифрование: cipher_program -d <входной файл> <выходной файл>" << endl;
    cout << endl;
    cout << "Параметры:" << endl;
    cout << "  -e, --encrypt  Режим шифрования" << endl;
    cout << "  -d, --decrypt  Режим дешифрования" << endl;
    cout << "  <входной файл>  Файл для обработки" << endl;
    cout << "  <выходной файл> Файл для сохранения результата" << endl;
    cout << endl;
    cout << "Примеры:" << endl;
    cout << "  cipher_program -e document.txt encrypted.bin" << endl;
    cout << "  cipher_program -d encrypted.bin decrypted.txt" << endl;
}

// Функция для получения пароля от пользователя
string GetPassword() {
    string password;
    cout << "Введите пароль: ";
    getline(cin, password);
    
    if (password.empty()) {
        cerr << "Ошибка: пароль не может быть пустым" << endl;
        exit(1);
    }
    
    return password;
}

// Функция для генерации ключа и IV из пароля
void DeriveKeyIV(const string& password, byte* key, byte* iv, size_t keyLength, size_t ivLength) {
    // Соль
    byte salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    // Генерация ключа из пароля
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, keyLength, 0, 
                   reinterpret_cast<const byte*>(password.data()), password.size(),
                   salt, sizeof(salt), 1000); // 1000 итераций
    
    // Генерация IV из пароля
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf_iv;
    pbkdf_iv.DeriveKey(iv, ivLength, 0,
                      reinterpret_cast<const byte*>(password.data()), password.size(),
                      salt, sizeof(salt), 1000);
}

// Функция шифрования файла
bool EncryptFile(const string& inputFile, const string& outputFile, const string& password) {
    try {
        // Чтение исходного файла
        ifstream inFile(inputFile, ios::binary);
        if (!inFile) {
            cerr << "Ошибка: не удалось открыть входной файл " << inputFile << endl;
            return false;
        }
        
        // Получение содержимого файла
        string plaintext;
        inFile.seekg(0, ios::end);
        plaintext.reserve(inFile.tellg());
        inFile.seekg(0, ios::beg);
        plaintext.assign((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());
        inFile.close();
        
        // Генерация ключа и IV
        const size_t keyLength = AES::DEFAULT_KEYLENGTH; // 16 байт для AES-128
        const size_t ivLength = AES::BLOCKSIZE; // 16 байт
        
        byte key[keyLength], iv[ivLength];
        DeriveKeyIV(password, key, iv, keyLength, ivLength);
        
        // Шифрование
        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, keyLength, iv, ivLength);
        
        string ciphertext;
        StringSource(plaintext, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(ciphertext)
            )
        );
        
        // Запись зашифрованных данных в файл
        ofstream outFile(outputFile, ios::binary);
        if (!outFile) {
            cerr << "Ошибка: не удалось создать выходной файл " << outputFile << endl;
            return false;
        }
        
        outFile.write(ciphertext.data(), ciphertext.size());
        outFile.close();
        
        cout << "Файл успешно зашифрован: " << outputFile << endl;
        cout << "Размер исходного файла: " << plaintext.size() << " байт" << endl;
        cout << "Размер зашифрованного файла: " << ciphertext.size() << " байт" << endl;
        
        return true;
        
    } catch(const exception& e) {
        cerr << "Ошибка при шифровании: " << e.what() << endl;
        return false;
    }
}

// Функция дешифрования файла
bool DecryptFile(const string& inputFile, const string& outputFile, const string& password) {
    try {
        // Чтение зашифрованного файла
        ifstream inFile(inputFile, ios::binary);
        if (!inFile) {
            cerr << "Ошибка: не удалось открыть входной файл " << inputFile << endl;
            return false;
        }
        
        // Получение содержимого файла
        string ciphertext;
        inFile.seekg(0, ios::end);
        ciphertext.reserve(inFile.tellg());
        inFile.seekg(0, ios::beg);
        ciphertext.assign((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());
        inFile.close();
        
        // Генерация ключа и IV (должны совпадать с использованными при шифровании)
        const size_t keyLength = AES::DEFAULT_KEYLENGTH;
        const size_t ivLength = AES::BLOCKSIZE;
        
        byte key[keyLength], iv[ivLength];
        DeriveKeyIV(password, key, iv, keyLength, ivLength);
        
        // Дешифрование
        CBC_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, keyLength, iv, ivLength);
        
        string decryptedtext;
        StringSource(ciphertext, true,
            new StreamTransformationFilter(decryptor,
                new StringSink(decryptedtext)
            )
        );
        
        // Запись расшифрованных данных в файл
        ofstream outFile(outputFile, ios::binary);
        if (!outFile) {
            cerr << "Ошибка: не удалось создать выходной файл " << outputFile << endl;
            return false;
        }
        
        outFile.write(decryptedtext.data(), decryptedtext.size());
        outFile.close();
        
        cout << "Файл успешно расшифрован: " << outputFile << endl;
        cout << "Размер зашифрованного файла: " << ciphertext.size() << " байт" << endl;
        cout << "Размер расшифрованного файла: " << decryptedtext.size() << " байт" << endl;
        
        return true;
        
    } catch(const exception& e) {
        cerr << "Ошибка при дешифровании: " << e.what() << endl;
        cerr << "Возможно, неверный пароль или файл поврежден" << endl;
        return false;
    }
}

int main(int argc, char* argv[]) {
    // Проверка количества аргументов
    if (argc != 4) {
        PrintHelp();
        return 1;
    }
    
    string mode = argv[1];
    string inputFile = argv[2];
    string outputFile = argv[3];
    
    // Проверка режима работы
    if (mode != "-e" && mode != "--encrypt" && mode != "-d" && mode != "--decrypt") {
        cerr << "Ошибка: неверный режим работы. Используйте -e для шифрования или -d для дешифрования" << endl;
        PrintHelp();
        return 1;
    }
    
    // Получение пароля
    string password = GetPassword();
    
    bool success = false;
    
    if (mode == "-e" || mode == "--encrypt") {
        cout << "Режим: ШИФРОВАНИЕ" << endl;
        cout << "Входной файл: " << inputFile << endl;
        cout << "Выходной файл: " << outputFile << endl;
        success = EncryptFile(inputFile, outputFile, password);
    } else {
        cout << "Режим: ДЕШИФРОВАНИЕ" << endl;
        cout << "Входной файл: " << inputFile << endl;
        cout << "Выходной файл: " << outputFile << endl;
        success = DecryptFile(inputFile, outputFile, password);
    }
    
    return success ? 0 : 1;
}