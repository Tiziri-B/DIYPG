
.RECIPEPREFIX = >
CC     = gcc
CFLAGS = -Wall -Wextra -g -Icommon -Irsa -Icodec
LDLIBS = -lm -lgmp

LIB_SRC  = $(wildcard common/*.c rsa/*.c codec/*.c)
LIB_OBJ  = $(patsubst %.c,build/%.o,$(LIB_SRC))
TEST_SRC = $(wildcard tests/test_*.c)
TEST_BIN = $(patsubst tests/%.c,build/%,$(TEST_SRC))

all: $(TEST_BIN)

build/%.o: %.c
> @mkdir -p $(dir $@)
> $(CC) $(CFLAGS) -c $< -o $@

$(TEST_BIN): build/%: tests/%.c $(LIB_OBJ)
> @mkdir -p build
> $(CC) $(CFLAGS) $< $(LIB_OBJ) -o $@ $(LDLIBS)

test: all
> @for t in $(TEST_BIN); do echo "== $$t"; ./$$t || exit 1; done

clean:
> rm -rf build

.PHONY: all test clean
