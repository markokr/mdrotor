
/*
 * SHA2 - fips180-2
 */

#include "mdrotor.h"
#include "result.h"

DEF_FULL_RESULT(256)
DEF_FULL_RESULT(512)

struct sha256_ctx {
	union {
		uint32_t words[16];
		uint8_t raw[16 * 4];
	} buf;
	union {
		uint32_t words[8];
		uint8_t raw[8 * 4];
	} final;
	struct RotorStack stk;
	struct Result16 *res16;
	struct Result256 *res;
	bool is_sha224;
};

struct sha512_ctx {
	union {
		uint64_t words[16];
		uint8_t raw[16 * 8];
	} buf;
	union {
		uint64_t words[8];
		uint8_t raw[8 * 8];
	} final;
	struct RotorStack stk;
	struct Result16 *res16;
	struct Result512 *res;
	bool is_sha384;
};

typedef struct sha256_ctx SHA256_CTX;
typedef struct sha512_ctx SHA512_CTX;

/*
 * initial values
 */

static const uint32_t H224[8] = {
	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
	0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
};

static const uint32_t H256[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

static const uint64_t H384[8] = {
	0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
	0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL,
};

static const uint64_t H512[8] = {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

/*
 * constants for mixing
 */

static const uint32_t K32[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint64_t K64[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

/*
 * mixing
 */

#define CH(x,y,z)  ((x & y) ^ ((~x) & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))

#define E32_0(x) (ror32(x,  2) ^ ror32(x, 13) ^ ror32(x, 22))
#define E32_1(x) (ror32(x,  6) ^ ror32(x, 11) ^ ror32(x, 25))
#define O32_0(x) (ror32(x,  7) ^ ror32(x, 18) ^ (x >> 3))
#define O32_1(x) (ror32(x, 17) ^ ror32(x, 19) ^ (x >> 10))

#define E64_0(x) (ror64(x, 28) ^ ror64(x, 34) ^ ror64(x, 39))
#define E64_1(x) (ror64(x, 14) ^ ror64(x, 18) ^ ror64(x, 41))
#define O64_0(x) (ror64(x,  1) ^ ror64(x,  8) ^ (x >> 7))
#define O64_1(x) (ror64(x, 19) ^ ror64(x, 61) ^ (x >> 6))

#define W(n)	(buf[(n) & 15])

#define SHA2_ROUND(_t, vtype, E0, E1, O0, O1, k) do { \
	vtype tmp1, tmp2, t = (_t); \
	if (t >= 16) { \
		W(t) = O1(W(t - 2)) + W(t - 7) + O0(W(t - 15)) + W(t - 16); \
	} else { \
		W(t) = ctx->buf.words[t]; \
	} \
	tmp1 = h + E1(e) + CH(e,f,g) + k[t] + W(t); \
	tmp2 = E0(a) + MAJ(a,b,c); \
	h = g; g = f; f = e; e = d + tmp1; d = c; c = b; b = a; a = tmp1 + tmp2; \
} while (0)

#define SHA256_ROUND(t) SHA2_ROUND(t, uint32_t, E32_0, E32_1, O32_0, O32_1, K32)
#define SHA512_ROUND(t) SHA2_ROUND(t, uint64_t, E64_0, E64_1, O64_0, O64_1, K64)

#define FINAL1(i, v) ctx->final.words[i] = v + IV[i]
#define FINAL() \
	FINAL1(0, a); FINAL1(1, b); FINAL1(2, c); FINAL1(3, d); \
	FINAL1(4, e); FINAL1(5, f); FINAL1(6, g); FINAL1(7, h)

static uint32_t REV256(struct sha256_ctx *ctx, const void *hash)
{
	const uint8_t *p = hash;
	uint32_t e = get32_be(p + 5*4);
	if (ctx->is_sha224)
		return e - H224[5];
	else
		return e - H256[5];
}

static uint32_t REV512(struct sha512_ctx *ctx, const void *hash)
{
	const uint8_t *p = hash;
	uint32_t e = get32_be(p + 5*8+4);
	if (ctx->is_sha384)
		return e - H384[5];
	else
		return e - H512[5];
}

/*
 * actual core
 */

static void sha256_core(struct sha256_ctx * ctx, const uint32_t *IV)
{
	uint32_t a = IV[0], b = IV[1], c = IV[2], d = IV[3];
	uint32_t e = IV[4], f = IV[5], g = IV[6], h = IV[7];
	uint32_t buf[16];

	R64(SHA256_ROUND, 0);
	if (!result16_check(ctx->res16, f)) return;
	FINAL();

	if (ctx->is_sha224)
		ctx->final.words[7] = 0;
	if (result256_check(ctx->res, ctx->final.raw)) {
		cpu2be_many32(ctx->final.words, 8);
		print_result(&ctx->stk, ctx->final.raw);
	}
}

static void sha512_core(struct sha512_ctx * ctx, const uint64_t *IV)
{
	uint64_t a = IV[0], b = IV[1], c = IV[2], d = IV[3];
	uint64_t e = IV[4], f = IV[5], g = IV[6], h = IV[7];
	uint64_t buf[16];

	R64(SHA512_ROUND, 0);
	R16(SHA512_ROUND, 64);
	if (!result16_check(ctx->res16, f)) return;
	FINAL();

	if (ctx->is_sha384)
		ctx->final.words[7] = ctx->final.words[6] = 0;
	if (result512_check(ctx->res, ctx->final.raw)) {
		cpu2be_many64(ctx->final.words, 8);
		print_result(&ctx->stk, ctx->final.raw);
	}
}

/*
 * set_char
 */

static inline void set_char32_fast(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	SHA256_CTX *ctx = stk->eng->priv;
#ifdef WORDS_BIGENDIAN
	ctx->buf.raw[char_pos] = c;
#else
	ctx->buf.raw[char_pos ^ 3] = c;
#endif
}

static inline void set_char64_fast(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	SHA512_CTX *ctx = stk->eng->priv;
#ifdef WORDS_BIGENDIAN
	ctx->buf.raw[char_pos] = c;
#else
	ctx->buf.raw[char_pos ^ 7] = c;
#endif
}

static void set_char32(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	set_char32_fast(stk, char_pos, c);
}

static void set_char64(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	set_char64_fast(stk, char_pos, c);
}

/*
 * set_length
 */

static void set_length32(struct RotorStack *stk, unsigned int len)
{
	SHA256_CTX *ctx = stk->eng->priv;
	set_char32(stk, len, 0x80);
	ctx->buf.words[15] = len * 8;
}

static void set_length64(struct RotorStack *stk, unsigned int len)
{
	SHA512_CTX *ctx = stk->eng->priv;
	set_char64(stk, len, 0x80);
	ctx->buf.words[15] = len * 8;
}

/*
 * init: 224, 256, 384, 512
 */

static void init256(struct EngineThread *eng)
{
	SHA256_CTX *ctx = zmalloc(sizeof(*ctx));
	eng->priv = ctx;

	stack_init(eng, &ctx->stk, 0);

	ctx->res = new_result256();
	ctx->res16 = new_result16();
}

static void init224(struct EngineThread *eng)
{
	SHA256_CTX *ctx;
	init256(eng);
	ctx = eng->priv;
	ctx->is_sha224 = true;
}

static void init512(struct EngineThread *eng)
{
	SHA512_CTX *ctx = zmalloc(sizeof(*ctx));
	eng->priv = ctx;

	stack_init(eng, &ctx->stk, 0);

	ctx->res = new_result512();
	ctx->res16 = new_result16();
}

static void init384(struct EngineThread *eng)
{
	SHA512_CTX *ctx;
	init512(eng);
	ctx = eng->priv;
	ctx->is_sha384 = true;
}

/*
 * release
 */

static void release32(struct EngineThread *eng)
{
	SHA256_CTX *ctx = eng->priv;
	result256_free(ctx->res);
	result16_free(ctx->res16);
	free(ctx);
}

static void release64(struct EngineThread *eng)
{
	SHA512_CTX *ctx = eng->priv;
	result512_free(ctx->res);
	result16_free(ctx->res16);
	free(ctx);
}

/*
 * add_hash
 */

static void add_hash32(struct EngineThread *eng, const void *hash)
{
	SHA256_CTX *ctx = eng->priv;
	uint32_t buf[8];
	int cnt = ctx->is_sha224 ? 7 : 8;
	memset(buf, 0, sizeof(buf));
	memcpy(buf, hash, cnt * 4);
	be2cpu_many32(buf, cnt);

	result256_add(ctx->res, buf);
	result16_add(ctx->res16, REV256(ctx, hash));
}

static void add_hash64(struct EngineThread *eng, const void *hash)
{
	SHA512_CTX *ctx = eng->priv;
	uint64_t buf[8];
	int cnt = ctx->is_sha384 ? 6 : 8;
	memset(buf, 0, sizeof(buf));
	memcpy(buf, hash, cnt * 8);
	be2cpu_many64(buf, cnt);
	result512_add(ctx->res, buf);
	result16_add(ctx->res16, REV512(ctx, hash));
}

/*
 * run
 */

static void run32(struct EngineThread *eng)
{
	SHA256_CTX *ctx = eng->priv;
	const uint32_t *iv = ctx->is_sha224 ? H224 : H256;
	result256_sort(ctx->res);
	while (eng->active) {
		sha256_core(ctx, iv);
		stack_turn(&ctx->stk, set_char32_fast);
	}
}

static void run64(struct EngineThread *eng)
{
	SHA512_CTX *ctx = eng->priv;
	const uint64_t *iv = ctx->is_sha384 ? H384 : H512;
	result512_sort(ctx->res);
	while (eng->active) {
		sha512_core(ctx, iv);
		stack_turn(&ctx->stk, set_char64_fast);
	}
}

/*
 * samples
 */

static const char * const samples224[] = {
	"cda1d665441ef8120c3d3e82610e74ab0d3b043763784676654d8ef1",
	"04215f2b34be7edccda218f2ad541ae6ca56c95d0514c40d0c57c0da",
	"d46d708cf9ad7ea8aa86a8d5f85428858fc9d2b4abfe479121a7203e",
	NULL
};

static const char * const samples256[] = {
	"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", // abc
	"688787d8ff144c502c7f5cffaafe2cc588d86079f9de88304c26b0cb99ce91c6", // asd
	"8e918ad19c46d3fff4a84ad43d4a218add297f7e5a34b60460e7fc173dbee62d", // fooz
	"364da3c52c2cad809907222abab391dc31b0e00c1e4202afdfebf45de15a2a6a", // bafaz
	NULL
};
static const char * const samples384[] = {
	"91389ee5448e9d7a00f2f250e3d83beff18f1177a04bd0a2019c27b0493bfa072130dfd1625c7b835d0bb008895272f8",
	"2966109d2670ddc3ba771d2e02e0685e95eaf50c5ecc6fd50ddf08acdcf5b4855848fb6a015a413bc37968505ebce869",
	"2719566d41ca3f8503fee2db4fef0ec5cbcf079e33614c1c6ce76a033145d91e2ffc51efcfb4635a89c3727e05d1d7b4",
	NULL
};

static const char * const samples512[] = {
	"e54ee7e285fbb0275279143abc4c554e5314e7b417ecac83a5984a964facbaad"
	"68866a2841c3e83ddf125a2985566261c4014f9f960ec60253aebcda9513a9b4", // asd
	"e44da7be76957a380f541ac6d28c0b2554c76aa8b36c5040c81596bc844d010c"
	"46dcedce88e0c2d0c88be8bfb4f65d105e498a910289cda170d36552d57fd33d", // fooz
	"64eb157177a341cd366245371dcd0975700e002773f88c773cd0f7cfd888bd0e"
	"09fbb723393a44d9fdb9a4a06c34fc74f672f435e3328757b3d9e3fcd1fe873c", // bafaz
	NULL
};

/*
 * engine defs
 */

const struct EngineInfo eng_sha224 = {
	.eng_name = "sha224plain", .algo_name = "sha224",
	.hash_len = 28,
	.init = init224,
	.release = release32,
	.add_hash = add_hash32,
	.run = run32,
	.set_char = set_char32,
	.set_length = set_length32,
	.sample_list = samples224,
};

const struct EngineInfo eng_sha256 = {
	.eng_name = "sha256plain", .algo_name = "sha256",
	.hash_len = 32,
	.init = init256,
	.release = release32,
	.add_hash = add_hash32,
	.run = run32,
	.set_char = set_char32,
	.set_length = set_length32,
	.sample_list = samples256,
};

const struct EngineInfo eng_sha384 = {
	.eng_name = "sha384plain", .algo_name = "sha384",
	.hash_len = 48,
	.init = init384,
	.release = release64,
	.add_hash = add_hash64,
	.run = run64,
	.set_char = set_char64,
	.set_length = set_length64,
	.sample_list = samples384,
};

const struct EngineInfo eng_sha512 = {
	.eng_name = "sha512plain", .algo_name = "sha512",
	.hash_len = 64,
	.init = init512,
	.release = release64,
	.add_hash = add_hash64,
	.run = run64,
	.set_char = set_char64,
	.set_length = set_length64,
	.sample_list = samples512,
};

