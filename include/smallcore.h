
/* sample */
#if 0

#define INIT_VAL	   (0)
#define HASH_STEP(prev, c) ((prev) * 33 + c)
#define REV_RESULT(res)    (res)

#endif


struct SmallCtx {
	uint32_t steps[MAX_LEN + 1]; // shifed offset + 1
	unsigned int hpos;
	struct RotorStack stk;
	struct Result32 *res;
	struct Result16 *res16;
	char word[MAX_LEN + 1];
};

/*
 * Standard API.
 */

static inline void set_char_fast(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	struct SmallCtx *ctx = stk->eng->priv;
	ctx->steps[char_pos + 1] = HASH_STEP(ctx->steps[char_pos], c);
	//ctx->word[char_pos] = c;
}

static void set_char(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	set_char_fast(stk, char_pos, c);
}

static void set_length(struct RotorStack *stk, unsigned int len)
{
	struct SmallCtx *ctx = stk->eng->priv;
	ctx->hpos = len; // ptr to last elem
}

static void init(struct EngineThread *eng)
{
	struct SmallCtx *ctx = zmalloc(sizeof(*ctx));
	eng->priv = ctx;
	stack_init(eng, &ctx->stk, 0);
	ctx->res = new_result32();
	ctx->res16 = new_result16();
	ctx->steps[0] = INIT_VAL;
}

static void release(struct EngineThread *eng)
{
	struct SmallCtx *ctx = eng->priv;
	result16_free(ctx->res16);
	result32_free(ctx->res);
	free(ctx);
}

static void add_hash(struct EngineThread *eng, const void *hash)
{
	struct SmallCtx *ctx = eng->priv;
	uint32_t val;
	memcpy(&val, hash, 4);
	val = REV_RESULT(ntohl(val));
	result32_add(ctx->res, val);
	result16_add(ctx->res16, val);
}

static void run(struct EngineThread *eng)
{
	struct SmallCtx *ctx = eng->priv;

	result32_sort(ctx->res);

	while (eng->active) {
		uint32_t res = ctx->steps[ctx->hpos];
		if (result16_check(ctx->res16, res)) {
			if (result32_check(ctx->res, res)) {
				res = htonl(FINAL_RESULT(res));
				print_result(&ctx->stk, &res);
			}
		}
		stack_turn(&ctx->stk, set_char_fast);
	}
}

#define SMALL_ENG(engname, samples) { \
	.eng_name = engname, .algo_name = engname, \
	.init = init, .release = release, \
	.add_hash = add_hash, .run = run, \
	.set_char = set_char, .set_length = set_length, \
	.hash_len = 4, .sample_list = samples \
}

