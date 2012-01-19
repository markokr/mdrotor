
# config
HAVE_SSE2 = yes
EXPERIMENTAL = no

#OPTFLAGS = -O2
OPTFLAGS = -O  -fomit-frame-pointer -ffast-math
#OPTFLAGS = -O2 -fomit-frame-pointer -ffast-math
#OPTFLAGS = -O3 -fomit-frame-pointer -ffast-math

WFLAGS =  -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers \
	  -Wmissing-prototypes -Wpointer-arith -Wendif-labels \
	  -Wdeclaration-after-statement -Wold-style-definition -Wstrict-prototypes \
	  -Wundef -Wformat -Wnonnull -Wstrict-overflow

CC = gcc
CC32 = gcc -m32 -march=core2 -fomit-frame-pointer
#CC32 = gcc -m32 -march=pentium4 -fomit-frame-pointer

WCC = i586-mingw32msvc-gcc -march=pentium4
WSTRIP = i586-mingw32msvc-strip
#WCC = winegcc -m32 -march=pentium4
WLIBS = -lwsock32

CFLAGS = -g $(OPTFLAGS) $(WFLAGS)
CPPFLAGS = -Iinclude "-DENG_LIST=$(ENG_LIST)" "-DDEF_LIST=$(DEF_LIST)"
LDFLAGS = -g
LIBS = -lpthread
HDRS = include/mdrotor.h include/result.h include/smallcore.h \
       include/sse2.h include/util.h include/sha2sse.h
SRCS = mdrotor.c util.c $(ESRCS)
ESRCS = $(SSE2_SRCS) normal/md5.c normal/sha1.c normal/sha2.c normal/test.c normal/crc32.c

ifeq ($(HAVE_SSE2),yes)
SSE2_SRCS = sse2/md5.c sse2/sha1.c sse2/sha256.c sse2/sha512.c
endif

ifeq ($(EXPERIMENTAL),yes)
ESRCS += $(wildcard test/*.c)
endif

# Quiet by default, 'make V=1' shows commands
V=0
ifeq ($(V), 0)
Q = @
E = @echo
else
Q =
E = @true
endif

# pick symbol list out of files
ENG_LIST := $(shell grep '^const[ ]struct[ ]EngineInfo[ ]' $(ESRCS) \
	| sed 's/.*EngineInfo[ ]*\([a-z_0-9]*\)*[ ]*=.*/\&\1,/')
DEF_LIST := $(shell grep '^const[ ]struct[ ]EngineInfo[ ]' $(ESRCS) \
	| sed 's/.*EngineInfo[ ]*\([a-z_0-9]*\)*[ ]*=.*/\1,/')

objs = $(addprefix lib/, $(SRCS:.c=.o))

wobjs = $(objs:.o=-w.o)
objs32 = $(objs:.o=-32.o)
asms = $(objs:.o=.s)


all: mdrotor

clean:
	rm -f *.[oas] lib/*.[oas] lib/*/*.[oas] core core.* mdrotor mdrotor.exe *.so

mdrotor.32: $(objs32)
	$(E) "	LD32" $@
	$(Q) $(CC32) -pthread -o $@ $(LDFLAGS) $(objs32) $(LIBS)
	@echo "Cmd: $(CC32) $(OPTFLAGS)"

mdrotor: $(objs)
	$(E) "	LD" $@
	$(Q) $(CC) -pthread -o $@ $(LDFLAGS) $(objs) $(LIBS)
	@echo "Cmd: $(CC) $(OPTFLAGS)"

$(objs): $(HDRS)

lib/%.o: %.c $(HDRS)
	$(E) "	CC" $<
	@mkdir -p lib/`dirname $<`
	$(Q) $(CC) -pthread $(CFLAGS) $(CPPFLAGS) -c $< -o $@

lib/%-w.o: %.c $(HDRS)
	$(E) "	WCC" $<
	@mkdir -p lib/`dirname $<`
	$(Q) $(WCC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS)

lib/%-32.o: %.c $(HDRS)
	$(E) "	CC32" $<
	@mkdir -p lib/`dirname $<`
	$(Q) $(CC32) -c $< -o $@ $(CPPFLAGS) $(CFLAGS)

icc:
	PATH=/opt/intel/cce/bin:$$PATH icc -march=core2 -fast -o mdrotor.icc $(SRCS) -lpthread $(CPPFLAGS)

exe: mdrotor.exe

mdrotor.exe: $(wobjs)
	$(E) "	WLD" $@
	$(Q) $(WCC) -g -o $@ $(wobjs) $(WLIBS)
	@$(WSTRIP) $@

asm: $(asms)

lib/%.s: %.c $(HDRS)
	$(E) "	ASM $@"
	@mkdir -p lib/sse2 lib/normal
	$(Q) $(CC) $(CFLAGS) $(CPPFLAGS) -fverbose-asm -S $< -o - \
	| sed -e '/^[.]L[^0-9][^0-9]/d' -e '/^[ 	]*[.]loc/d' > $@

tgz:
	tar czf mdrotor.tgz README Makefile $(HDRS) $(SRCS)

memcheck: mdrotor
	valgrind --log-file=v.log --leak-check=full --leak-resolution=high ./mdrotor -B


