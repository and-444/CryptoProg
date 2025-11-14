CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LIBS = -lcrypto++

# Имя исполняемого файла
TARGET = cipher_program

# Исходные файлы
SRCS = cipher_main.cpp
OBJS = $(SRCS:.cpp=.o)

# Цель по умолчанию
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Очистка собранных файлов
clean:
	rm -f $(OBJS) $(TARGET) test_plain.txt test_encrypted.bin test_decrypted.txt

# Установка зависимостей
install-deps:
	sudo apt-get update
	sudo apt-get install libcrypto++-dev libcrypto++-utils

# Тестирование программы
test: $(TARGET)
	@echo "Создание тестового файла..."
	echo "Это тестовый файл для проверки шифрования." > test_plain.txt
	echo "Вторая строка тестовых данных." >> test_plain.txt
	@echo "Шифрование..."
	./$(TARGET) -e test_plain.txt test_encrypted.bin
	@echo "Дешифрование..."
	./$(TARGET) -d test_encrypted.bin test_decrypted.txt
	@echo "Сравнение исходного и дешифрованного файлов..."
	diff test_plain.txt test_decrypted.txt && echo "ТЕСТ ПРОЙДЕН: Файлы идентичны!" || echo "ТЕСТ НЕ ПРОЙДЕН: Файлы различаются!"

.PHONY: all clean install-deps test