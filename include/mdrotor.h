
#include "util.h"


#define MAX_LEN 32

struct EngineInfo;
struct EngineThread;
struct RotorStack;
struct TopRotor;
struct Rotor;

/* read-only */
struct EngineInfo {
        const char *eng_name;
	const char *algo_name;
        void (*init)(struct EngineThread *);
        void (*release)(struct EngineThread *);
        void (*add_hash)(struct EngineThread *eng, const void *);
        void (*run)(struct EngineThread *);
        void (*set_length)(struct RotorStack *stk, unsigned int len);
        void (*set_char)(struct RotorStack *stk, unsigned int char_pos, unsigned int c);
        int hash_len;
	const char * const *sample_list;
};

struct EngineThread {
	const struct EngineInfo *info;
	struct TopRotor *top;

	void *priv; // engine private data

	bool stopped;
	int active; // nr of active stacks
	uint32_t counter;
	uint32_t last_counter;
	pthread_t thread;
	struct EngineThread *next;
};

/* shared between threads, needs locking */
struct TopRotor {
	pthread_mutex_t lock;
	int nrotors;			// how many chars
	int angle;			// idx of first char
	bool stopped;
	int wlen;			// number of chars in wiring
	int start_len;
	int end_len;
	int *step_list;
	int *wiring;
};

struct Rotor {
	const int *wiring;	// variants to try
	const int *step;	// idx->followup idx
	int angle;		// current idx into wiring
	int pos;		// char nr
};

/* one or more per thread */
struct RotorStack {
	int nrotors;
	bool stopped;
	struct EngineThread *eng;
	struct Rotor subzero;
	struct Rotor stack_[MAX_LEN + 1]; // 1-based array
	int id;
};

#define get_rotor(stk, n) (&(stk)->stack_[(n) + 1])

#define stack_turn(stk, set_char) do { \
	struct Rotor *r = get_rotor(stk, (stk)->nrotors - 1); \
	if (r->step[r->angle] > 0) { \
		r->angle = r->step[r->angle]; \
		set_char(stk, r->pos, r->wiring[r->angle]); \
	} else stack_turn_many(r); \
} while (0)

void stack_turn_many(struct Rotor *r);

/* subgen init, fills initial string */
void stack_init(struct EngineThread *eng, struct RotorStack *stk, unsigned int id);
void print_result(struct RotorStack *stk, const void *hash);

