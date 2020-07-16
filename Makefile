# Headers
SHELL_INCLS = common.h list.h listproc.h signal.h
# Sources
SHELL_SRCS = shell.c common.c list.c listproc.c signal.c
# Only libs name
SHELL_LIBS =
# Executable name
SHELL_NAME = shell
# Build folder
BUILD_DIR = 
# BUILD_DIR =

# C compiler
CC = gcc
# Compile flags
CFLAGS = -Wall -g
# Objects name
SHELL_OBJS = $(addprefix $(BUILD_DIR), $(SHELL_SRCS:.c=.o))
# Reasign libs
SHELL_CCLIBS = $(addprefix -l, $(SHELL_LIBS))
# Target
SHELL_TARGET = $(addprefix $(BUILD_DIR), $(SHELL_NAME))

.PHONY: all
all: $(SHELL_TARGET)

# Compile the objects when any source changes
$(BUILD_DIR)%.o: %.c $(INCLS)
	$(CC) -c -o $@ $(CFLAGS) $<

# Link the objects and generate the executable
$(SHELL_TARGET): $(SHELL_OBJS)	
	$(CC) -o $(SHELL_TARGET) $(SHELL_INCLS) $(SHELL_OBJS) $(SHELL_CCLIBS)

.PHONY: clean
clean:
	rm -f $(SHELL_TARGET) $(SHELL_OBJS)
