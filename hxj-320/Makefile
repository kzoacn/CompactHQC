ifeq ($(ROOT),)
ROOT:=.
endif

CC=gcc

CFLAGS:=-O3 -Wall -Wextra -Wpedantic -Wvla -Wredundant-decls -std=c99

SHA3_SRC:=$(ROOT)/lib/fips202/fips202.c
SHA3_INCLUDE:=-I $(ROOT)/lib/fips202

SRC:=$(ROOT)/src/
INCLUDE:=-I $(ROOT)/src -pthread
LIB:=$(SHA3_INCLUDE)

MAIN_HXJ:=$(ROOT)/src/main_hxj.c
MAIN_KAT:=$(ROOT)/src/main_kat.c

HXJ_OBJS:=aes.o aes-gcm.o vector.o reed_muller.o reed_solomon.o fft.o gf.o gf2x.o code.o parsing.o hxj.o kem.o dem.o shake_ds.o shake_prng.o toom.o toom-gpl.o ccapke.o
HXJ_OBJS_VERBOSE:=vector.o reed_muller.o reed_solomon-verbose.o fft.o gf.o gf2x.o code-verbose.o parsing.o hxj-verbose.o kem-verbose.o shake_ds.o shake_prng.o
LIB_OBJS:= fips202.o

BIN:=bin
BUILD:=bin/build


folders:
	@echo -e "\n### Creating folders\n"
	mkdir -p $(BUILD)

fips202.o: | folders
	@/bin/echo -e "\n### Compiling fips202"
	$(CC) $(CFLAGS) -c $(SHA3_SRC) $(SHA3_INCLUDE) -o $(BUILD)/$@

%.o: $(SRC)/%.c | folders
	@/bin/echo -e "\n### Compiling $@"
	$(CC) $(CFLAGS) -c $< $(INCLUDE) $(LIB) -o $(BUILD)/$@

%.o: $(SRC)/%.cpp | folders
	@/bin/echo -e "\n### Compiling $@ (C++)"
	$(CPP) $(CPP_FLAGS) -c $< $(INCLUDE) $(LIB) -o $(BUILD)/$@

%-verbose.o: $(SRC)/%.c | folders
	@echo -e "\n### Compiling $@ (verbose mode)\n"
	$(CC) $(CFLAGS) -c $< $(INCLUDE) $(LIB) -D VERBOSE -o $(BUILD)/$@

%-verbose.o: $(SRC)/%.cpp | folders
	@echo -e "\n### Compiling $@ (verbose C++)\n"
	$(CPP) $(CPP_FLAGS) -c $< $(INCLUDE) $(LIB) -D VERBOSE -o $(BUILD)/$@

hxj-320: $(HXJ_OBJS) $(LIB_OBJS) | folders
	@echo -e "\n### Compiling hxj-320\n"
	$(CC) $(C_FLAGS) $(MAIN_HXJ) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@

hxj-320-kat: $(HXJ_OBJS) $(LIB_OBJS) | folders
	@echo -e "\n### Compiling hxj-320 KAT\n"
	$(CPP) $(CPP_FLAGS) $(MAIN_KAT) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@

hxj-320-verbose: $(HXJ_OBJS_VERBOSE) $(LIB_OBJS) | folders
	@echo -e "\n### Compiling hxj-320 (verbose mode)\n"
	$(CPP) $(CPP_FLAGS) $(MAIN_HXJ) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -D VERBOSE -o $(BIN)/$@


clean:
	rm -f PQCkemKAT_*
	rm -f vgcore.*
	rm -rf ./bin
