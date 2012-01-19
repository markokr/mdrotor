
/*
 * SHA256, SHA256 for SSE2
 */

#include "mdrotor.h"
#include "result.h"

#define SSE2BITS 32
#include "sse2.h"

#define E0S1 2
#define E0S2 13
#define E0S3 22
#define E1S1 6
#define E1S2 11
#define E1S3 25

#define O0S1 7
#define O0S2 18
#define O0S3 3
#define O1S1 17
#define O1S2 19
#define O1S3 10

#include "sha2sse.h"

DEF_FULL_RESULT(256)

struct sha256_ctx {
	SVAL buf[16];
	SVAL final[8];
	struct RotorStack stk[4];
	struct SSResult *sres;
	struct Result256 *res;
	bool stripped;
};
typedef struct sha256_ctx SHA256_CTX;

static void check_result(SHA256_CTX *ctx)
{
	int i;
	uint32_t hash[8];
	struct RotorStack *stk;

	for (i = 0; i < 4; i++) {
		stk = &ctx->stk[i];
		if (stk->stopped) continue;
		hash[0] =  htonl(ctx->final[0].words[i]);
		hash[1] =  htonl(ctx->final[1].words[i]);
		hash[2] =  htonl(ctx->final[2].words[i]);
		hash[3] =  htonl(ctx->final[3].words[i]);
		hash[4] =  htonl(ctx->final[4].words[i]);
		hash[5] =  htonl(ctx->final[5].words[i]);
		hash[6] =  htonl(ctx->final[6].words[i]);
		hash[7] =  htonl(ctx->final[7].words[i]);
		if (result256_check(ctx->res, hash))
			print_result(&ctx->stk[i], hash);
	}
}

static inline void dump_ctx(SHA256_CTX *ctx)
{
	dump_svals("sha256.buf", 16, ctx->buf);
}

static const SVAL H224[8] = {
	C32(0xc1059ed8), C32(0x367cd507), C32(0x3070dd17), C32(0xf70e5939),
	C32(0xffc00b31), C32(0x68581511), C32(0x64f98fa7), C32(0xbefa4fa4),
};

static const SVAL H256[8] = {
	C32(0x6a09e667), C32(0xbb67ae85), C32(0x3c6ef372), C32(0xa54ff53a),
	C32(0x510e527f), C32(0x9b05688c), C32(0x1f83d9ab), C32(0x5be0cd19),
};

static const SVAL K[64] = {
	C32(0x428a2f98), C32(0x71374491), C32(0xb5c0fbcf), C32(0xe9b5dba5),
	C32(0x3956c25b), C32(0x59f111f1), C32(0x923f82a4), C32(0xab1c5ed5),
	C32(0xd807aa98), C32(0x12835b01), C32(0x243185be), C32(0x550c7dc3),
	C32(0x72be5d74), C32(0x80deb1fe), C32(0x9bdc06a7), C32(0xc19bf174),
	C32(0xe49b69c1), C32(0xefbe4786), C32(0x0fc19dc6), C32(0x240ca1cc),
	C32(0x2de92c6f), C32(0x4a7484aa), C32(0x5cb0a9dc), C32(0x76f988da),
	C32(0x983e5152), C32(0xa831c66d), C32(0xb00327c8), C32(0xbf597fc7),
	C32(0xc6e00bf3), C32(0xd5a79147), C32(0x06ca6351), C32(0x14292967),
	C32(0x27b70a85), C32(0x2e1b2138), C32(0x4d2c6dfc), C32(0x53380d13),
	C32(0x650a7354), C32(0x766a0abb), C32(0x81c2c92e), C32(0x92722c85),
	C32(0xa2bfe8a1), C32(0xa81a664b), C32(0xc24b8b70), C32(0xc76c51a3),
	C32(0xd192e819), C32(0xd6990624), C32(0xf40e3585), C32(0x106aa070),
	C32(0x19a4c116), C32(0x1e376c08), C32(0x2748774c), C32(0x34b0bcb5),
	C32(0x391c0cb3), C32(0x4ed8aa4a), C32(0x5b9cca4f), C32(0x682e6ff3),
	C32(0x748f82ee), C32(0x78a5636f), C32(0x84c87814), C32(0x8cc70208),
	C32(0x90befffa), C32(0xa4506ceb), C32(0xbef9a3f7), C32(0xc67178f2),
};

static inline uint32_t REV256(struct sha256_ctx *ctx, const void *hash) {
	const uint32_t *p = hash;
	uint32_t f = ntohl(p[5]);
	if (ctx->stripped)
		return f - H224[5].words[0];
	else
		return f - H256[5].words[0];
}


static void sha256_core(struct sha256_ctx * ctx, const SVAL *iv)
{
	__m128i a, b, c, d, e, f, g, h;
	SVAL buf[64];

	R16(COPY, 0);
	R16(PREPARE, 16);
	R16(PREPARE, 32);
	R16(PREPARE, 48);

	a = sval_load(&iv[0]);
	b = sval_load(&iv[1]);
	c = sval_load(&iv[2]);
	d = sval_load(&iv[3]);
	e = sval_load(&iv[4]);
	f = sval_load(&iv[5]);
	g = sval_load(&iv[6]);
	h = sval_load(&iv[7]);

	R64(SHA2ROUND, 0);

	if (!ssresult_check(ctx->sres, f)) return;

	FINAL(0, a);
	FINAL(1, b);
	FINAL(2, c);
	FINAL(3, d);
	FINAL(4, e);
	FINAL(5, f);
	FINAL(6, g);
	if (!ctx->stripped) {
		FINAL(7, h);
	}
	check_result(ctx);
}

/*
 * Standard API.
 */

static inline void set_char_fast(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	SHA256_CTX *ctx = stk->eng->priv;
	int wpos = char_pos / 4;
	int bpos = (char_pos & 3) ^ 3;
	ctx->buf[wpos].raw32[stk->id][bpos] = c;
}

static void set_char(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	set_char_fast(stk, char_pos, c);
}

static void set_length(struct RotorStack *stk, unsigned int len)
{
	SHA256_CTX *ctx = stk->eng->priv;
	ctx->buf[len / 4].raw32[stk->id][(len & 3) ^ 3] = 0x80;
	ctx->buf[15].words[stk->id] = len * 8;
}

static void init256(struct EngineThread *eng)
{
	SHA256_CTX *ctx = _mm_malloc(sizeof(*ctx), 16);
	eng->priv = ctx;
	memset(ctx, 0, sizeof(*ctx));

	stack_init(eng, &ctx->stk[0], 0);
	stack_init(eng, &ctx->stk[1], 1);
	stack_init(eng, &ctx->stk[2], 2);
	stack_init(eng, &ctx->stk[3], 3);

	ctx->res = new_result256();
	ctx->sres = ssresult_new();
}

static void init224(struct EngineThread *eng)
{
	SHA256_CTX *ctx;
	init256(eng);
	ctx = eng->priv;
	ctx->stripped = 1;
}

static void release(struct EngineThread *eng)
{
	SHA256_CTX *ctx = eng->priv;
	result256_free(ctx->res);
	ssresult_free(ctx->sres);
	_mm_free(ctx);
}

static void add_hash(struct EngineThread *eng, const void *hash)
{
	char buf[32];
	SHA256_CTX *ctx = eng->priv;
	memset(buf, 0, sizeof(buf));
	memcpy(buf, hash, eng->info->hash_len);
	result256_add(ctx->res, buf);
	ssresult_add32(ctx->sres, REV256(ctx, buf));
}

static void run(struct EngineThread *eng)
{
	SHA256_CTX *ctx = eng->priv;
	const SVAL *iv = ctx->stripped ? H224 : H256;

	result256_sort(ctx->res);

	while (eng->active) {
		sha256_core(ctx, iv);
		stack_turn(&ctx->stk[0], set_char_fast);
		stack_turn(&ctx->stk[1], set_char_fast);
		stack_turn(&ctx->stk[2], set_char_fast);
		stack_turn(&ctx->stk[3], set_char_fast);
	}
}

static const char * const samples256[] = {
	"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", // abc
	"688787d8ff144c502c7f5cffaafe2cc588d86079f9de88304c26b0cb99ce91c6", // asd
	"8e918ad19c46d3fff4a84ad43d4a218add297f7e5a34b60460e7fc173dbee62d", // fooz
	"364da3c52c2cad809907222abab391dc31b0e00c1e4202afdfebf45de15a2a6a", // bafaz
	NULL,
};

static const char * const samples224[] = {
	"cda1d665441ef8120c3d3e82610e74ab0d3b043763784676654d8ef1",
	"04215f2b34be7edccda218f2ad541ae6ca56c95d0514c40d0c57c0da",
	"d46d708cf9ad7ea8aa86a8d5f85428858fc9d2b4abfe479121a7203e",
	NULL
};


const struct EngineInfo eng_sha256sse = {
	.eng_name = "sha256sse", .algo_name = "sha256",
	.hash_len = 32,
	.init = init256,
	.release = release,
	.add_hash = add_hash,
	.run = run,
	.set_char = set_char,
	.set_length = set_length,
	.sample_list = samples256,
};

const struct EngineInfo eng_sha224sse = {
	.eng_name = "sha224sse", .algo_name = "sha224",
	.hash_len = 32 - 4,
	.init = init224,
	.release = release,
	.add_hash = add_hash,
	.run = run,
	.set_char = set_char,
	.set_length = set_length,
	.sample_list = samples224,
};

