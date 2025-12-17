#ifndef SM4_H
#define SM4_H

#include <stdint.h>

// SM4 上下文结构体
// 用来存放扩展后的 32 个轮密钥 (Round Keys)
typedef struct {
    uint32_t rk[32]; 
} sm4_context;

// --- API 接口 ---

// 密钥设置 (Day 4 实现)
void sm4_set_key(sm4_context *ctx, const uint8_t *key);

// 加密/解密 (Day 4 实现)
void sm4_encrypt(sm4_context *ctx, const uint8_t *input, uint8_t *output);
void sm4_decrypt(sm4_context *ctx, const uint8_t *input, uint8_t *output);

#endif // SM4_H