NAME    := cmls
DEPS    := jansson openssl
CFLAGS  := $(CFLAGS)  -Wall -Wextra -Werror -g
LDFLAGS := $(LDFLAGS)

################################################################################

ifdef DEPS
CFLAGS  += $(shell pkg-config --cflags $(DEPS))
LDFLAGS += $(shell pkg-config --libs   $(DEPS))
endif

SRCD := src
BLDD := build

SRCS := $(patsubst $(SRCD)/%,%,$(shell find src -name '*.c'))
INCS := $(patsubst %.c,$(BLDD)/%.d,$(SRCS))
OBJS := $(patsubst %.c,$(BLDD)/%.o,$(SRCS))
DIRS := $(sort $(shell dirname $(OBJS)))

$(shell mkdir -p $(DIRS))

all: $(NAME)

-include $(INCS)

$(BLDD)/%.o: $(SRCD)/%.c
	$(CC) $(CFLAGS) -c $< -MMD -o $@

$(NAME): $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

run: $(NAME)
	./$<
.PHONY: run

test: $(NAME)
	valgrind --track-origins=yes ./$< testall
.PHONY: test

install: $(NAME)
	mkdir -p $(out)/bin
	cp $< $(out)/bin
.PHONY: install

clean:
	rm -rf $(BLDD) $(NAME)
	@echo $(SRCS)
	@echo $(OBJS)
.PHONY: clean
