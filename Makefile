NAME = ft_shield

#########
RM = rm -rf
CC = cc
CFLAGS = -Werror -Wextra -Wall -Os
LDFLAGS = -lm -s
RELEASE_CFLAGS = $(CFLAGS) -DNDEBUG
PASS ?= 1234 # if no pass is given, use 1234 e.g. make PASS=1234 or export PASS=1234
HASHED_PWD = echo -n $(PASS) | md5sum | head -c 32

#########

#########
FILES = main md5 ft_malloc log

SRC = $(addsuffix .c, $(FILES))

vpath %.c srcs inc
#########

#########
OBJ_DIR = objs
OBJ = $(addprefix $(OBJ_DIR)/, $(SRC:.c=.o))
DEP = $(addsuffix .d, $(basename $(OBJ)))
#########

#########
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	${CC} -MMD $(CFLAGS) -DPWD=\"$(shell $(HASHED_PWD))\" -c -Iinc  $< -o $@

all: 
	$(MAKE) $(NAME)

$(NAME): $(OBJ) Makefile
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME) $(LDFLAGS)
	@echo "EVERYTHING DONE  "
	@echo "PWD: $(PASS) HASHED_PWD: $(shell $(HASHED_PWD))"

release: CFLAGS = $(RELEASE_CFLAGS)
release: re
	@echo "RELEASE BUILD DONE  "

clean:
	$(RM) $(OBJ) $(DEP)
	$(RM) -r $(OBJ_DIR)
	@echo "OBJECTS REMOVED   "

fclean: clean
	$(RM) $(NAME)
	@echo "EVERYTHING REMOVED   "

re:	fclean all

.PHONY: all clean fclean re release

-include $(DEP)
