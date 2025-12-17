#include <stdio.h>
#include <string.h>
#include <time.h> 
#include "sm4.h"

// 打印字节数组的辅助函数
void print_hex(const char *label, const uint8_t *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    printf("=== SM4 Full Encryption Test ===\n\n");

    // 1. 定义标准测试向量 (GM/T 0002-2012 附录 A.1)
    // 密钥
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    // 明文
    uint8_t input[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    // 标准答案 (密文)
    uint8_t expected_output[16] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };

    uint8_t output[16];     // 存放加密结果
    uint8_t decrypted[16];  // 存放解密结果
    sm4_context ctx;

    printf("[Test Case] Standard Verification\n");
    print_hex("Key       ", key, 16);
    print_hex("Plaintext ", input, 16);
    print_hex("Expected  ", expected_output, 16);
    printf("------------------------------------------------\n");

    // 2. 执行加密
    sm4_set_key(&ctx, key);          // 生成密钥
    sm4_encrypt(&ctx, input, output); // 加密

    print_hex("Ciphertext", output, 16);

    // 3. 验证加密结果
    if (memcmp(output, expected_output, 16) == 0) {
        printf("\n✅ ENCRYPTION SUCCESS! (Matches Standard)\n");
    } else {
        printf("\n❌ ENCRYPTION FAILED!\n");
        return 1;
    }

    // 4. 执行解密 (自测)
    sm4_set_key(&ctx, key);          // 重新设置密钥(其实没必要，ctx里已经有了，为了演示流程)
    sm4_decrypt(&ctx, output, decrypted); // 解密

    print_hex("Decrypted ", decrypted, 16);

    // 5. 验证解密结果
    if (memcmp(decrypted, input, 16) == 0) {
        printf("✅ DECRYPTION SUCCESS! (Restored Plaintext)\n");
    } else {
        printf("❌ DECRYPTION FAILED!\n");
        return 1;
    }

    printf("\n------------------------------------------------\n");
    printf("[Performance Benchmark]\n");
    
    // 测试参数：跑 100 万轮 (1 Million Rounds)
    // 数据量 = 1,000,000 * 16 bytes ≈ 15.2 MB
    //long rounds = 1000000;
    // 目标：加密 1GB 数据
    // 1 GB = 1024 * 1024 * 1024 字节 = 1,073,741,824 字节
    // 每次加密 16 字节，所以需要跑 67,108,864 轮
    long rounds = 67108864;
    size_t total_bytes = rounds * 16;
    double total_mb = (double)total_bytes / (1024 * 1024);

    printf("Running %ld encryption rounds (%.2f MB data)...\n", rounds, total_mb);

    // 开始计时
    clock_t start_time = clock();

    // 疯狂循环
    // 注意：我们重复加密同一个 buffer，为了测试纯算法性能，避免内存拷贝成为瓶颈
    for (long i = 0; i < rounds; i++) {
        sm4_encrypt(&ctx, input, output);
    }

    // 结束计时
    clock_t end_time = clock();

    // 计算结果
    double elapsed_sec = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    double speed = total_mb / elapsed_sec;

    printf("Time Elapsed : %.4f seconds\n", elapsed_sec);
    printf("Throughput   : %.2f MB/s\n", speed);
    printf("------------------------------------------------\n");


    return 0;
}