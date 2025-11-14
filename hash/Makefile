CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LIBS = -lcrypto++

# Имя исполняемого файла
TARGET = hash_program

# Исходные файлы
SRCS = hash_main.cpp
OBJS = $(SRCS:.cpp=.o)

# Цель по умолчанию
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Очистка собранных файлов
clean:
	rm -f $(OBJS) $(TARGET)

# Установка зависимостей
install-deps:
	sudo apt-get update
	sudo apt-get install libcrypto++-dev libcrypto++-utils

.PHONY: all clean install-deps