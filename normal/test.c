
#include "mdrotor.h"

static int eng_id = 0;

/* test engine private data */
struct TestEng {
	struct RotorStack stack;
	char word[256];
};

static void test_set_char(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	struct TestEng *my = stk->eng->priv;
	printf("#%d: set_char(%d, '%c')\n", stk->id, char_pos, c);
	my->word[char_pos] = c;
}

static void test_set_length(struct RotorStack *stk, unsigned int len)
{
	printf("#%d: set_length(%d)\n", stk->id, len);
}

static void test_init(struct EngineThread *eng)
{
	struct TestEng *my = zmalloc(sizeof(*my));
	eng->priv = my;

	printf("test_init\n");

	stack_init(eng, &my->stack, eng_id++);
}

static void test_release(struct EngineThread *eng)
{
	struct TestEng *my = eng->priv;
	free(my);
	eng->priv = NULL;
}

int blah;

static void calc(const char *word)
{
	char buf[256];
	int i, j;
	strcpy(buf, word);
	for (j = 0; j < 16; j++)
	for (i = 0; i < 256; i++)
		blah += buf[i];
}

static void test_run(struct EngineThread *eng)
{
	struct TestEng *my;
	FILE *f;
	char fn[256];
	printf("test_run: %p\n", eng);
	my = eng->priv;
	snprintf(fn, sizeof(fn), "zz.eng%d.txt", my->stack.id);
	//f = fopen(fn, "wb");
	f = stdout;
	while (eng->active) {
		printf("test_loop\n");
		calc(my->word);
		fprintf(f,"%s (eng %d)\n", my->word, my->stack.id);
		stack_turn(&my->stack, test_set_char);
	}
	//fclose(f);
}

static void test_add_hash(struct EngineThread *eng, const void *hash)
{
}

static const char *samples[] = {"817433a5", NULL};

const struct EngineInfo eng_test = {
	.eng_name = "testeng", .algo_name = "test",
	.hash_len = 4,
	.init = test_init,
	.release = test_release,
	.add_hash = test_add_hash,
	.run = test_run,
	.set_length = test_set_length,
	.set_char = test_set_char,
	.sample_list = samples,
};

