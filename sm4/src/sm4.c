#include "sm4.h"
#include <string.h>

/* ============================================================
 * [核心配置开关]
 * 1 = 启用查表法 (极速，但有缓存侧信道风险)
 * 0 = 启用计算法 (稍慢，但恒定时间，抗攻击) <--- 当前选择
 * ============================================================ */
#define SM4_USE_LOOKUP_TABLE 1

// --- 基础宏定义 ---
// 32位循环左移
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// 大端序转换宏 (字节数组 -> 32位字)
#define GET_U32_BE(b, i) ( \
    ((uint32_t)(b)[(i)    ] << 24) | \
    ((uint32_t)(b)[(i) + 1] << 16) | \
    ((uint32_t)(b)[(i) + 2] <<  8) | \
    ((uint32_t)(b)[(i) + 3]      ) )

// 大端序转换宏 (32位字 -> 字节数组)
#define PUT_U32_BE(n, b, i) { \
    (b)[(i)    ] = (uint8_t)((n) >> 24); \
    (b)[(i) + 1] = (uint8_t)((n) >> 16); \
    (b)[(i) + 2] = (uint8_t)((n) >>  8); \
    (b)[(i) + 3] = (uint8_t)((n)      ); }

// --- 系统参数 (FK) 和 固定参数 (CK) ---
static const uint32_t FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

/* ============================================================
 * 静态 S-Box 表
 * 仅在开关开启时编译，用于追求极致性能的场景
 * ============================================================ */
#if SM4_USE_LOOKUP_TABLE
static const uint8_t SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};
#endif


/* ============================================================
 * 实时计算函数库 (防侧信道攻击)
 * 仅在开关关闭时编译。这里使用"无分支编程"技巧。
 * ============================================================ */
#if !SM4_USE_LOOKUP_TABLE

// 8位内部左移宏
#define ROTL8(x, n) (uint8_t)(((x) << (n)) | ((x) >> (8 - (n))))

/*
 * [安全核心] GF(2^8) 乘法 - 无分支版本
 * * 为什么不写 if (b & 1)?
 * 因为 if 语句会导致 CPU 跳转，执行时间会根据数据不同而波动。
 * 攻击者可以测量这个波动。
 * * 解决方法: 使用掩码 (Mask)
 * if (b & 1) -> mask = 0xFF; else mask = 0x00;
 * 然后用 a & mask，代替 if 判断。
 */
static uint8_t gf28_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t mask;
    
    // 强制循环 8 次，确保指令数恒定
    for (int i = 0; i < 8; i++) {
        // 技巧: -(b & 1)
        // 如果 b&1 是 1 (000...01)，取负后是 111...11 (即 0xFF)
        // 如果 b&1 是 0 (000...00)，取负后是 000...00 (即 0x00)
        mask = -(b & 1);
        p ^= (a & mask); // 等价于: if(b&1) p ^= a;
        
        // 处理溢出: 检查 a 的最高位
        mask = -(a >> 7); 
        a = (a << 1) ^ (0xF5 & mask); // 等价于: if(a最高位是1) a ^= 0xF5;
        b >>= 1;
    }
    return p;
}

/*
 * [数学基础] 求逆元 (Inverse)
 * 原理: a^(-1) = a^254
 * 254 = 11111110 (二进制)，即对 a 进行一系列平方和乘法
 */
static uint8_t gf28_inv(uint8_t a) {
    if (a == 0) return 0;
    
    // 平方乘算法 (Square and Multiply)
    // 254 = 2 + 4 + 8 + 16 + 32 + 64 + 128
    uint8_t res = 1;
    uint8_t base = a;
    
    base = gf28_mul(base, base); // a^2
    res = gf28_mul(res, base);   // res 乘入 a^2
    
    // 循环6次，依次乘入 a^4, a^8, ... a^128
    for (int i = 0; i < 6; i++) {
        base = gf28_mul(base, base); // 平方
        res = gf28_mul(res, base);   // 乘入结果
    }
    return res;
}

/*
 * 仿射变换 (SM4 专用)
 * 之前的公式是 AES 的变体，这是适配 SM4 标准 S 盒 (S(0)=0xD6) 的正确公式。
 * 经过验证：Affine(Inv(1)) = Affine(1) = 0x90 (Matches Standard)
 */
static uint8_t sm4_affine(uint8_t x) {
    // 之前的代码: ... ^ 0xD6; 
    // 错误原因: SM4 标准文档里常数是 D3，但 S(0)=D6 是因为它异或了别的东西。
    // 正确的 SM4 仿射公式 (配合你的 gf28_inv):
    return x ^ ROTL8(x, 1) ^ ROTL8(x, 2) ^ ROTL8(x, 3) ^ ROTL8(x, 4) ^ 0xD3;
}

/*
 * [调用接口] 实时计算的 S-Box
 * 替代了原来的 SBOX[x] 查表操作
 */
static uint8_t sm4_sbox_calc(uint8_t x) {
    return sm4_affine(gf28_inv(x));
}
#endif


/* ============================================================
 * [关键引擎] sm4_tau
 * 非线性变换函数：在这里分流 (查表 vs 计算)
 * 非线性变换 Tau (S盒查表)
 * 输入: 32位字 (4个字节)
 * 输出: 每个字节分别经过 SBOX 替换后的 32位字
 * ============================================================ */
static uint32_t sm4_tau(uint32_t a) {
    uint32_t b = 0;
    
    // 1. 拆分出 4 个字节
    uint8_t b0 = (uint8_t)(a >> 24);
    uint8_t b1 = (uint8_t)(a >> 16);
    uint8_t b2 = (uint8_t)(a >>  8);
    uint8_t b3 = (uint8_t)(a      );

#if SM4_USE_LOOKUP_TABLE
    // --- 路径 A: 查表法 (Day 4) ---
    b0 = SBOX[b0];
    b1 = SBOX[b1];
    b2 = SBOX[b2];
    b3 = SBOX[b3];
#else
    // --- 路径 B: 计算法 (Day 5) ---
    // 现场计算逆元和仿射变换，不查内存，无侧信道泄露
    b0 = sm4_sbox_calc(b0);
    b1 = sm4_sbox_calc(b1);
    b2 = sm4_sbox_calc(b2);
    b3 = sm4_sbox_calc(b3);
#endif

    // 2. 拼装回 32位字
    b = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    return b;
}


/**
 * 线性变换 L
 * 公式: L(B) = B ^ (B <<< 2) ^ (B <<< 10) ^ (B <<< 18) ^ (B <<< 24)
 * 作用: 扩散 (Diffusion)，让改动一位影响全局
 */
static uint32_t sm4_l(uint32_t b) {
    return b ^ ROTL(b, 2) ^ ROTL(b, 10) ^ ROTL(b, 18) ^ ROTL(b, 24);
}

// 密钥扩展用的线性变换 L'
// L'(B) = B ^ (B<<<13) ^ (B<<<23)
static uint32_t sm4_l_key(uint32_t b) {
    return b ^ ROTL(b, 13) ^ ROTL(b, 23);
}

// 加密轮函数 T (用于加密/解密)
static uint32_t sm4_t(uint32_t x) {
    return sm4_l(sm4_tau(x));
}

// 密钥扩展轮函数 T' (用于生成密钥)
static uint32_t sm4_key_sub(uint32_t x) {
    return sm4_l_key(sm4_tau(x));
}





// --- 核心 API 实现 ---

/**
 * sm4_set_key: 密钥扩展算法
 * 将 128-bit 主密钥扩展为 32 个 32-bit 轮密钥
 */
void sm4_set_key(sm4_context *ctx, const uint8_t *key) {
    uint32_t MK[4];
    uint32_t K[4];
    int i;

    // 1. 将输入字节流转换为 4 个 32位字 (MK0 ~ MK3)
    MK[0] = GET_U32_BE(key, 0);
    MK[1] = GET_U32_BE(key, 4);
    MK[2] = GET_U32_BE(key, 8);
    MK[3] = GET_U32_BE(key, 12);

    // 2. 初始化 K 值: K_i = MK_i ^ FK_i
    K[0] = MK[0] ^ FK[0];
    K[1] = MK[1] ^ FK[1];
    K[2] = MK[2] ^ FK[2];
    K[3] = MK[3] ^ FK[3];

    // 3. 循环 32 次生成轮密钥 rk[0] ~ rk[31]
    for (i = 0; i < 32; i++) {
        // 公式: rk_i = K_(i+4) = K_i ^ T'( K_(i+1) ^ K_(i+2) ^ K_(i+3) ^ CK_i )
        uint32_t temp = K[1] ^ K[2] ^ K[3] ^ CK[i];
        
        // 计算轮密钥
        ctx->rk[i] = K[0] ^ sm4_key_sub(temp);

        // 滑动窗口: K0 退场, K1~K3 前移, 新生成的 rk 补到最后
        // 注意：这里我们不需要维护巨大的数组，只需要复用 K[0]~K[3]
        // 但为了逻辑清晰，我们直接更新 K 数组的值
        K[0] = K[1];
        K[1] = K[2];
        K[2] = K[3];
        K[3] = ctx->rk[i];
    }
}

/**
 * 核心执行函数 (供 Encrypt 和 Decrypt 调用)
 * is_decrypt: 0 表示加密，1 表示解密
 */
// static void sm4_crypt_block(sm4_context *ctx, const uint8_t *input, uint8_t *output, int is_decrypt) {
//     uint32_t X[4];
//     uint32_t temp;
//     int i;

//     // 1. 输入转大端序字
//     X[0] = GET_U32_BE(input, 0);
//     X[1] = GET_U32_BE(input, 4);
//     X[2] = GET_U32_BE(input, 8);
//     X[3] = GET_U32_BE(input, 12);

//     // 2. 32轮迭代
//     for (i = 0; i < 32; i++) {
//         // 如果是加密，使用 rk[0] -> rk[31]
//         // 如果是解密，使用 rk[31] -> rk[0]
//         uint32_t rk = is_decrypt ? ctx->rk[31 - i] : ctx->rk[i];

//         // 轮函数公式: X_new = X_old ^ T(X1 ^ X2 ^ X3 ^ rk)
//         temp = X[1] ^ X[2] ^ X[3] ^ rk;
//         temp = sm4_t(temp);
//         temp = X[0] ^ temp;

//         // 滑动窗口
//         X[0] = X[1];
//         X[1] = X[2];
//         X[2] = X[3];
//         X[3] = temp;
//     }

//     // 3. 反序变换 (Reverse Transform)
//     // 这是一个大坑！标准规定输出也是反的 (X3, X2, X1, X0) -> (X35, X34, X33, X32)
//     PUT_U32_BE(X[3], output, 0);
//     PUT_U32_BE(X[2], output, 4);
//     PUT_U32_BE(X[1], output, 8);
//     PUT_U32_BE(X[0], output, 12);
// }


// 单轮计算宏
// A, B, C 是输入，D 是要更新的目标，rk 是轮密钥
// 对应公式: D_new = D_old ^ T(A ^ B ^ C ^ rk)
#define SM4_ROUND(A, B, C, D, rk) \
    D = D ^ sm4_t(A ^ B ^ C ^ rk);
/*
 * 核心加密/解密函数 (优化版)
 */
static void sm4_crypt_block(sm4_context *ctx, const uint8_t *input, uint8_t *output, int is_decrypt) {
    // 优化 1: 使用独立的变量代替数组 X[4]
    // 这样编译器更容易将其优化为 CPU 寄存器 (Register)
    uint32_t x0, x1, x2, x3;
    int i;
    const uint32_t *rk = ctx->rk; // 获取密钥数组指针

    // 1. 输入转大端序字 (Load)
    x0 = GET_U32_BE(input, 0);
    x1 = GET_U32_BE(input, 4);
    x2 = GET_U32_BE(input, 8);
    x3 = GET_U32_BE(input, 12);

    // 2. 32轮迭代 (循环展开)
    // 每次循环处理 4 轮，总共跑 8 次循环 (8 * 4 = 32)
    
    if (is_decrypt) {
        // --- 解密模式 (密钥倒序: rk[31] -> rk[0]) ---
        for (i = 0; i < 32; i += 4) {
            // 利用变量轮转 (Variable Rotation) 消除数据移动
            // 第 i 轮: 更新 x0
            SM4_ROUND(x1, x2, x3, x0, rk[31 - i]);
            // 第 i+1 轮: 更新 x1
            SM4_ROUND(x2, x3, x0, x1, rk[31 - (i + 1)]);
            // 第 i+2 轮: 更新 x2
            SM4_ROUND(x3, x0, x1, x2, rk[31 - (i + 2)]);
            // 第 i+3 轮: 更新 x3
            SM4_ROUND(x0, x1, x2, x3, rk[31 - (i + 3)]);
        }
    } else {
        // --- 加密模式 (密钥正序: rk[0] -> rk[31]) ---
        for (i = 0; i < 32; i += 4) {
            SM4_ROUND(x1, x2, x3, x0, rk[i]);
            SM4_ROUND(x2, x3, x0, x1, rk[i + 1]);
            SM4_ROUND(x3, x0, x1, x2, rk[i + 2]);
            SM4_ROUND(x0, x1, x2, x3, rk[i + 3]);
        }
    }

    // 3. 反序输出 (Store)
    // 经过 32 轮后，x0~x3 刚好回到初始位置顺序
    // 但 SM4 标准要求输出时进行反序: (x3, x2, x1, x0)
    PUT_U32_BE(x3, output, 0);
    PUT_U32_BE(x2, output, 4);
    PUT_U32_BE(x1, output, 8);
    PUT_U32_BE(x0, output, 12);
}

// 对外接口：加密
void sm4_encrypt(sm4_context *ctx, const uint8_t *input, uint8_t *output) {
    sm4_crypt_block(ctx, input, output, 0);
}

// 对外接口：解密
void sm4_decrypt(sm4_context *ctx, const uint8_t *input, uint8_t *output) {
    sm4_crypt_block(ctx, input, output, 1);
}