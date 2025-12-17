CC = gcc
CFLAGS = -Wall -O3 -I./include -flto

# 目标文件
TARGET = sm4_app

# 源文件
SRCS = src/sm4.c src/main.c

# 默认编译任务
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

# 清理规则
clean:
	rm -f $(TARGET)