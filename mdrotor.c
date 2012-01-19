
#include "mdrotor.h"

#if 1
#define get_time() get_real_time()
#else
#define get_time() get_user_time(tnum)
#endif

#ifdef __linux__
#include <sched.h>
static void conf_sched(void)
{
	cpu_set_t set;
	int res, i;

	CPU_ZERO(&set);
	res = sched_getaffinity(0, sizeof(set), &set);
	if (res < 0)
		die("sched_getaffinity");
	for (i = 0; i < 256; i++) {
		if (!CPU_ISSET(i, &set))
			continue;
		printf("allowed cpu: %d\n", i);
	}
}
#else
static void conf_sched(void)
{
}
#endif

#ifndef DEF_LIST
#define DEF_LIST eng_md5sse, eng_md5std, eng_crc32,
#endif
#ifndef ENG_LIST
#define ENG_LIST &eng_md5sse, &eng_md5std, &eng_crc32,
#endif

#define STAT_DURATION (1*USEC)

extern struct EngineInfo DEF_LIST dummy;
static const struct EngineInfo * const eng_info_list[] = { ENG_LIST NULL };

static bool benchmark = false;
static usec_t bench_dur = 5*USEC;
static usec_t bench_warmup = USEC/2;
static int bench_trycnt = 2;
static int bench_got_results = 0;


static const int top_step[1] = { 0 };

static const char usage_str[] =
"usage: mdrotor [-h|-V|-M] [-t nthreads] [-c chars] [-f hashfile] [hash ...]\n"
"  -l N  -l M-N  set start and end length\n"
"  -t NTHREADS   set number of threads (default: 1 per cpu)\n"
"  -f HASHFILE   read hashes from file (1 per line)\n"
"  -e engname    use engine\n"
"  -E            show engine list\n"
"  -T            run tests\n"
"  -h            show help\n"
;

static void usage(int err)
{
	printf(usage_str);
	exit(err);
}

static void banner(void)
{
	printf("mdrotor v0.1 (");
#ifdef __SSE2__
	printf("SSE2:%s ", cpu_has_sse2() ? "yes" : "no");
#endif
	printf("nCPU:%d)\n", get_number_of_cpus());
}

static void show_eng_list(void)
{
	int i;
	const struct EngineInfo *e;
	for (i = 0; eng_info_list[i]; i++) {
		e = eng_info_list[i];
		printf("%-16s %s\n", e->algo_name, e->eng_name);
	}
	exit(0);
}

static const struct EngineInfo *find_eng(const char *name)
{
	int i;
	const struct EngineInfo *e;
	for (i = 0; eng_info_list[i]; i++) {
		e = eng_info_list[i];
		if (strcmp(name, e->algo_name) == 0)
			return e;
		if (strcmp(name, e->eng_name) == 0)
			return e;
	}
	printf("Engine '%s' not found\n", name);
	exit(1);
}

void print_result(struct RotorStack *stk, const void *hash)
{
	char word[256];
	char hex[256];
	int hash_len = stk->eng->info->hash_len;
	struct Rotor *r;
	int i;
	if (benchmark) {
		bench_got_results++;
		return;
	}
	bin2hex(hash, hash_len, hex, sizeof(hex));
	for (i = 0; i < stk->nrotors; i++) {
		r = get_rotor(stk, i);
		word[i] = r->wiring[r->angle];
	}
	word[i] = 0;
	printf("\rfound a match: %s -- \"%s\"\n", hex, word);
}

static void top_lock(struct TopRotor *top)
{
	if (pthread_mutex_lock(&top->lock) != 0)
		die("pthread_mutex_lock");
}

static void top_unlock(struct TopRotor *top)
{
	if (pthread_mutex_unlock(&top->lock) != 0)
		die("pthread_mutex_unlock");
}

static void set_length(struct RotorStack *stk, unsigned len)
{
	stk->nrotors = len;
	stk->eng->info->set_length(stk, stk->nrotors);
}

static void rotate_many(struct RotorStack *stk, struct Rotor *r)
{
	for (; r->pos < stk->nrotors; r++) {
		r->angle = r->step[r->angle];
		stk->eng->info->set_char(stk, r->pos, r->wiring[r->angle]);
	}
}

static void top_rotate(struct RotorStack *stk)
{
	struct TopRotor *top = stk->eng->top;
	struct Rotor *r;

	top_lock(top);

	if (top->stopped) {
		stk->stopped = true;
		stk->eng->active--;
		goto done;
	}

	if (top->nrotors < top->start_len) {
		top->nrotors = top->start_len;
	} else if (top->angle + 1 < top->wlen) {
		top->angle++;
	} else if (top->nrotors < top->end_len) {
		top->nrotors++;
		top->angle = 0;
	} else {
		top->stopped = true;
		stk->stopped = true;
		stk->eng->active--;
		goto done;
	}

	if (top->nrotors > stk->nrotors)
		set_length(stk, top->nrotors);

	r = get_rotor(stk, 0);
	r->wiring = top->wiring + top->angle;
	rotate_many(stk, r);
done:
	top_unlock(top);
}

/* w is cur pos that got new idx=0 */
void stack_turn_many(struct Rotor *r)
{
	struct RotorStack *stk = container_of(r, struct RotorStack, stack_[r->pos + 1]);
	if (stk->stopped)
		return;
	stk->eng->counter += stk->eng->top->wlen;
	for (r--; r->pos > 0; r--) {
		if (r->step[r->angle] > 0) {
			rotate_many(stk, r);
			return;
		}
	}

	top_rotate(stk);
}

void stack_init(struct EngineThread *eng, struct RotorStack *stk, unsigned int id)
{

	struct TopRotor *top = eng->top;
	struct Rotor *r;
	int i;

	memset(stk, 0, sizeof(*stk));
	stk->eng = eng;
	stk->id = id;
	stk->eng->active++;

	r = get_rotor(stk, -1);
	r->step = top_step;
	r->wiring = top->wiring;
	r->pos = -1;
	r = get_rotor(stk, 0);
	r->step = top_step;
	r->wiring = top->wiring;

	for (i = 1; i < MAX_LEN; i++) {
		r = get_rotor(stk, i);
		r->pos = i;
		r->wiring = top->wiring;
		r->step = top->step_list;
		r->angle = top->wlen - 1;
	}

	if (top->nrotors == 0) { // first
		top->nrotors = top->start_len;
		set_length(stk, top->nrotors);
		if (top->start_len == 0) {
			top->start_len++;
		} else {
			rotate_many(stk, r);
		}
	} else {
		set_length(stk, top->nrotors);
		top_rotate(stk);
	}
}

/*
 * Common code
 */

static void *eng_launcher(void *arg)
{
	struct EngineThread *eng = arg;
	eng->info->run(eng);
	eng->stopped = true;
	return NULL;
}

static void eng_run(struct EngineThread *eng)
{
	pthread_create(&eng->thread, NULL, eng_launcher, eng);
}

static void eng_finish(struct EngineThread *eng)
{
	if (!eng->stopped)
		die("eng_finish on running thread?");
	if (pthread_join(eng->thread, NULL) != 0)
		die("pthread_join");

	eng->info->release(eng);
	free(eng);
}

static struct EngineThread *new_thread(const struct EngineInfo *info, struct TopRotor *top)
{
	struct EngineThread *eng;

	eng = zmalloc(sizeof(*eng));
	eng->info = info;
	eng->top = top;

	eng->info->init(eng);

	return eng;
}

static struct TopRotor *top_init(int start, int end, const char *char_list)
{
	int i, j, a, b, *step_list, *w, *wend;
	const unsigned char *p = (unsigned char *)char_list;
	struct TopRotor *top = zmalloc(sizeof(*top));

	if (!*char_list)
		die("no chars");

	if (pthread_mutex_init(&top->lock, NULL) != 0)
		die("pthread_mutex_init");
	top->start_len = start;
	top->end_len = end;

	w = zmalloc(256 * sizeof(int));
	wend = w + 256;
	top->wiring = w;

	while (*p && w < wend) {
		if (p[1] == '-' && p[2]) {
			a = p[0], b = p[2];
			if (a > b) die("bad order for chars");
			for (j = a; j <= b && w < wend; j++)
				*w++ = j;
			p += 3;
		} else {
			*w++ = *p++;
		}
	}
	if (w >= wend && *p)
		die("too many chars?");
	top->wlen = w - top->wiring;

	step_list = zmalloc(top->wlen * sizeof(int));
	for (i = 0; i < top->wlen - 1; i++)
		step_list[i] = i + 1;
	step_list[i] = 0;
	top->step_list = step_list;

	return top;
}

static void top_free(struct TopRotor *top)
{
	pthread_mutex_destroy(&top->lock);
	free(top->step_list);
	free(top->wiring);
	free(top);
}

static void add_hash(const char *hash, struct EngineThread *eng)
{
	unsigned char buf[1024];
	int len = hex2bin(hash, buf, sizeof(buf));

	for (; eng; eng = eng->next) {
		if (len != eng->info->hash_len)
			die("bad hash len");
		eng->info->add_hash(eng, buf);
	}
}

static bool eng_maint(struct EngineThread *eng, struct TopRotor *top, int tnum)
{
	static usec_t last_time = 0;
	static uint64_t last_cnt = 0;
	static double total_count, total_time;

	unsigned long long avg;
	usec_t t, dur;
	uint32_t cur, cnt;
	bool done = true;
	const char *unit;
	double avgx;

	for (; eng; eng = eng->next) {
		if (eng->stopped)
			continue;

		done = false;
		cur = eng->counter;
		cnt = cur - eng->last_counter;
		eng->last_counter = cur;
		last_cnt += cnt;
	}
	if (done)
		goto finish;

	t = get_time();
	if (!last_time) {
		last_time = t;
		last_cnt = 0;
		return true;
	};

	dur = t - last_time;
	if (dur < STAT_DURATION)
		return true;

	/* print avg */
	avg = last_cnt * USEC / dur;
	avgx = avg;
	if (avgx > 1000000000) {
		avgx /= 1000000000;
		unit = "Gh/s";
	} else if (avg > 1000000) {
		avgx /= 1000000;
		unit = "Mh/s";
	} else if (avg > 1000) {
		avgx /= 1000;
		unit = "kh/s";
	} else {
		unit = "h/s";
	}
	printf("\rLen: %d  Speed: %0.3f %s \r", top->nrotors, avgx, unit);
	fflush(stdout);

	total_time += dur;
	total_count += last_cnt;

	last_time = t;
	last_cnt = 0;
	return true;

finish: /* all done, report avg */
	printf("\nAll done, average speed: %.02f h/sec\n", total_count * USEC / total_time);
	return false;
}

static void parse_len(const char *arg, int *p_start, int *p_end)
{
	int res;
	if (strchr(arg, '-')) {
		res = sscanf(arg, "%u-%u", p_start, p_end);
		if (res != 2)
			goto failed;
	} else {
		res = sscanf(arg, "%u", p_start);
		*p_end = *p_start;
		if (res != 1)
			goto failed;
	}
	if (*p_end < *p_start || *p_start < 0 || *p_end > MAX_LEN)
		goto failed;
	return;
failed:
	die("bad format for length");
}

static uint64_t run_eng_bench_real(const struct EngineInfo *info, int tnum)
{
	int i;
	struct TopRotor *top;
	struct EngineThread *eng_list = NULL, *eng;
	usec_t t_launch, t_start = 0, t_end, t_now;
	bool warmup = true;
	unsigned long long total = 0;

	/* init generator & threads */
	top = top_init(8, 12, "a-zA-Z0-9");
	for (i = 0; i < tnum; i++) {
		eng = new_thread(info, top);
		eng->next = eng_list;
		eng_list = eng;
	}
	for (i = 0; info->sample_list[i]; i++) {
		add_hash(info->sample_list[i], eng_list);
	}
	for (eng = eng_list; eng; eng = eng->next)
		eng_run(eng);

	/* main loop */
	t_launch = get_time();
	while (1) {
		usleep(500000);
		t_now = get_time();
		if (warmup) {
			if (t_now < t_launch + bench_warmup)
				continue;
			warmup = false;
			t_start = t_now;
			for (eng = eng_list; eng; eng = eng->next)
				eng->last_counter = eng->counter;
		} else if (t_now > t_start + bench_dur)
			break;
	}
	t_end = t_now;
	for (eng = eng_list; eng; eng = eng->next) {
		total += eng->counter - eng->last_counter;
		eng->active = 0;
	}

	/* wait for threads to finish */
	while (1) {
		usleep(500000);
		for (eng = eng_list; eng; eng = eng->next)
			if (!eng->stopped)
				continue;
		break;
	}

	/* all done, free resources */
	for (eng = eng_list; eng; ) {
		eng_list = eng->next;
		eng->info->release(eng);
		free(eng);
		eng = eng_list;
	}
	top_free(top);
	return (total * USEC / (t_end - t_start));
}

static void run_eng_bench(const struct EngineInfo *info, int tnum)
{
	int try;
	char name[256];
	unsigned long long total_avg = 0, avg;

	if (bench_trycnt < 1)
		die("bad count\n");

	bench_got_results = 0;
	snprintf(name, sizeof(name), "%s/%s", info->algo_name, info->eng_name);
	printf("%-20s..", name);
	fflush(stdout);

	for (try = 0; try < bench_trycnt; try++) {
		avg = run_eng_bench_real(info, tnum);
		total_avg += avg;
		//if (try) printf("  ");
		printf(" %10llu", avg);
		fflush(stdout);
	}

	printf("   avg:%10llu h/s\n", total_avg / bench_trycnt);
}

static void run_bench_all(int tnum)
{
	const char *done[256], *a;
	int i, j, donecnt = 0;
	const struct EngineInfo *e;

	for (i = 0; eng_info_list[i]; i++) {
		a = eng_info_list[i]->algo_name;

		if (!strcmp(a, "sha224")) continue;
		if (!strcmp(a, "sha384")) continue;
		if (!strcmp(a, "test")) continue;

		// is done?
		for (j = 0; j < donecnt; j++) {
			if (strcmp(a, done[j]) == 0)
				goto skip;
		}
		// now all engs with this algo
		for (j = 0; eng_info_list[j]; j++) {
			e = eng_info_list[j];
			if (strcmp(e->algo_name, a) != 0)
				continue;
			run_eng_bench(e, tnum);
		}
		done[donecnt++] = a;
skip:;
	}
	exit(0);
}

static void run_bench(const char *name, int tnum)
{
	int i, done = 0;
	const struct EngineInfo *e;

	benchmark = true;
	printf("doing %dx%ds testrun with %d thread(s)\n\n",
	       bench_trycnt, (int)(bench_dur / USEC), tnum);

	if (name == NULL)
		run_bench_all(tnum);

	for (i = 0; eng_info_list[i]; i++) {
		e = eng_info_list[i];
		if (name && strcmp(name, e->algo_name) == 0)
			goto doit;
		if (name && strcmp(name, e->eng_name) == 0)
			goto doit;
		if (name)
			continue;
doit:
		run_eng_bench(e, tnum);
		done++;
	}
	if (!done) {
		printf("no engines found\n");
		exit(1);
	} else {
		exit(0);
	}
}

int main(int argc, char *argv[])
{
	const char *eng_name = NULL;
	const struct EngineInfo *info;

	struct TopRotor *top;
	struct EngineThread *eng_list = NULL, *eng;
	int tnum = -1, i, opt;
	uint32_t hashcnt;
	char *infile = NULL;
	bool do_test = false, do_bench = false;
	int l_start = 0, l_end = 8;
	char *char_list = "a-zA-Z0-9";

	while ((opt = getopt(argc, argv, "BC:D:ETc:e:f:hl:t:")) != -1) {
		switch (opt) {
		case 'B': do_bench = 1; break;
		case 'D': bench_dur = USEC * atoi(optarg); break;
		case 'C': bench_trycnt = atoi(optarg); break;
		case 'h': usage(0); break;
		case 't': tnum = atoi(optarg); break;
		case 'c': char_list = optarg; break;
		case 'f': infile = optarg; break;
		case 'E': show_eng_list(); break;
		case 'e': eng_name = optarg; break;
		case 'T': do_test = true; break;
		case 'l': parse_len(optarg, &l_start, &l_end); break;
		default: usage(1); break;
		}
	}

	/* detect cpu count */
	if (tnum < 1)
		tnum = get_number_of_cpus();
	if (tnum < 1) {
		tnum = 1;
	}

	conf_sched();

	banner();

	if (do_bench)
		run_bench(eng_name, tnum);

	if (!eng_name)
		eng_name = "crc32";

	info = find_eng(eng_name);

	/* init generator & threads */
	top = top_init(l_start, l_end, char_list);
	for (i = 0; i < tnum; i++) {
		eng = new_thread(info, top);
		eng->next = eng_list;
		eng_list = eng;
	}

	/* add hashes */
	hashcnt = 0;
	while (optind < argc) {
		add_hash(argv[optind++], eng_list);
		hashcnt++;
	}
	if (infile) {
		FILE *f = fopen(infile, "rt");
		char buf[1024];

		while (1) {
			int len;
			char *ln = fgets(buf, sizeof(buf), f);
			if (!ln)
				break;
			len = strlen(ln);
			if (!len)
				die("binary file?");
			if (ln[len - 1] != '\n')
				die("invalid line");
			ln[len - 1] = 0;
			add_hash(ln, eng_list);
			hashcnt++;
		}
	}

	if (do_test && info->sample_list) {
		for (i = 0; info->sample_list[i]; i++) {
			add_hash(info->sample_list[i], eng_list);
			hashcnt++;
		}
	}

	if (hashcnt < 1)
		die("please provide some hashes");
	printf("Loaded %d hashes\n", hashcnt);
	printf("Range: %d..%d, Chars(%d): %s\n",
	       top->start_len, top->end_len,
	       top->wlen, "-");
	printf("Starting %d threads, engine %s\n", tnum, info->eng_name);
	printf("----------------------\n");

	for (eng = eng_list; eng; eng = eng->next)
		eng_run(eng);

	while (1) {
		usleep(500000);
		if (!eng_maint(eng_list, top, tnum))
			break;
	}

	for (eng = eng_list; eng; ) {
		eng_list = eng->next;
		eng_finish(eng);
		eng = eng_list;
	}
	top_free(top);

	return 0;
}

