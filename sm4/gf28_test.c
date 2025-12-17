#include <stdio.h>
#include <stdint.h>

/**
 * SM4 的核心数学常数
 * 不可约多项式 f(x) = x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1
 * 二进制表示: 1 1111 0101
 * 去掉最高位 x^8 后，低8位为: 1111 0101，即十六进制 0xF5
 */
#define SM4_POLY 0xF5

/**
 * 函数: gf28_multiply
 * 功能: 计算两个字节在 GF(2^8) 域上的乘积
 * 输入: a, b (两个操作数)
 * 输出: 乘积结果
 */
uint8_t gf28_multiply(uint8_t a, uint8_t b) {
    uint8_t p = 0; // 累加器，用于存放最终结果
    uint8_t i;

    // 循环8次，处理 b 的每一位 (从最低位到最高位)
    for (i = 0; i < 8; i++) {
        // 1. 判断 b 的最低位是否为 1
        // 如果是 1，说明这一项需要累加到结果中
        // 在有限域中，累加(加法) 就是 异或(^)
        if (b & 1) {
            p ^= a;
        }

        // 2. 准备计算下一次的 a (即 a * x)
        // 先检查 a 的最高位(第8位)是否为 1
        // 因为左移后，如果最高位丢失，说明发生了溢出(超过 x^7 到达 x^8)，需要模约减
        uint8_t high_bit = a & 0x80;

        // 3. a 左移一位 (相当于乘以 x)
        a <<= 1;

        // 4. 如果刚才最高位是 1，则需要异或不可约多项式
        // 相当于: a = a - f(x) (在域中减法也是异或)
        if (high_bit) {
            a ^= SM4_POLY;
        }

        // 5. b 右移一位，准备处理下一位
        b >>= 1;
    }

    return p;
}

int main() {
    printf("=== Day 1: GF(2^8) Math Lab (SM4 Version) ===\n");
    printf("Irreducible Polynomial: x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1 (0xF5)\n\n");

    // --- 测试用例 1: 基础乘法 ---
    // 0x02 * 0x03 = 0x02 * (2 + 1) = 0x04 ^ 0x02 = 0x06
    uint8_t a1 = 0x02;
    uint8_t b1 = 0x03;
    printf("[Test 1] Simple: 0x%02x * 0x%02x = 0x%02x (Expected: 0x06)\n", a1, b1, gf28_multiply(a1, b1));

    // --- 测试用例 2: 溢出测试 (验证 SM4 多项式) ---
    // 0x80 (x^7) * 0x02 (x) = x^8
    // 在模 f(x) 下，x^8 = f(x) - x^8 = x^7 + x^6 + x^5 + x^4 + x^2 + 1 = 0xF5
    uint8_t a2 = 0x80;
    uint8_t b2 = 0x02;
    printf("[Test 2] Overflow: 0x%02x * 0x%02x = 0x%02x (Expected: 0xf5)\n", a2, b2, gf28_multiply(a2, b2));

    // --- 测试用例 3: 随机验证 ---
    // 0x57 * 0x83 (这是AES的一个经典例子，但在SM4下结果会不同)
    uint8_t a3 = 0x57;
    uint8_t b3 = 0x83;
    printf("[Test 3] Complex: 0x%02x * 0x%02x = 0x%02x\n", a3, b3, gf28_multiply(a3, b3));

    return 0;
}