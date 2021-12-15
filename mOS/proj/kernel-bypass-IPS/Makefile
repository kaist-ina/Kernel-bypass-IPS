DEBUG_MODE ?= 0

### mOS Settings ###
MTCP_FLD    = ../../core
MTCP_INC    = -I$(MTCP_FLD)/include
MTCP_TARGET = $(MTCP_FLD)/lib/libmtcp.a
LIB_DIR     += -L$(MTCP_FLD)/lib
UTIL_INC    = -I../../util/include

LIBS    += -m64 -pthread -march=native -Wl,-export-dynamic -L../../drivers/dpdk/lib -Wl,-lnuma -Wl,-lmtcp -Wl,-lpthread -Wl,-lrt -Wl,-ldl -Wl,$(shell cat ../../drivers/dpdk/lib/ldflags.txt)
LIBS +=  -Wl,--whole-archive -lhugetlbfs -Wl,--no-whole-archive -ldl -lhugetlbfs_privutils

COMMON_CFLAGS := -m64 -march=native -std=c++11

ifeq ($(DEBUG_MODE), 1)
        COMMON_CFLAGS += -O0 -g
		COMMON_CFLAGS += -Wno-write-strings
else
        COMMON_CFLAGS += -O3
		COMMON_CFLAGS += -Wno-write-strings #-Wall -Werror
endif

######## Common Settings ########
Common_Cpp_Files := $(wildcard Common/*.cpp)
Common_Cpp_Objects := $(Common_Cpp_Files:.cpp=.o)

######## Kernel-bypass-IPS Settings ########
Kernel-bypass-IPS_Cpp_Files := $(wildcard Kernel-bypass-IPS/*.cpp)
Kernel-bypass-IPS_Include_Paths := -IKernel-bypass-IPS -ICommon $(MTCP_INC) $(UTIL_INC)
Kernel-bypass-IPS_Cpp_Flags := $(COMMON_CFLAGS) $(Kernel-bypass-IPS_Include_Paths) 
Kernel-bypass-IPS_Link_Flags := $(COMMON_CFLAGS) $(LIB_DIR) $(LIBS)
Kernel-bypass-IPS_Cpp_Objects := $(Kernel-bypass-IPS_Cpp_Files:.cpp=.o)
Kernel-bypass-IPS := ips

ifeq ($(DEBUG_MODE), 0)
all: $(Kernel-bypass-IPS)
	@echo "The project has been built in release mode."
else
all: $(Kernel-bypass-IPS)
	@echo "The project has been built in debug mode."
endif

######## mOS Objects ########
$(MTCP_TARGET):
	cd $(MTCP_FLD)/src && make

######## Common Objects ########
Common/%.o: Common/%.cpp
	@$(CXX) $(COMMON_CFLAGS) -c $< -o $@
	@echo "CXX  <=  $<"

######## Kernel-bypass-IPS Objects ########
Kernel-bypass-IPS/%.o: Kernel-bypass-IPS/%.cpp $(MTCP_TARGET)
	@$(CXX) $(Kernel-bypass-IPS_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Kernel-bypass-IPS): $(Common_Cpp_Objects) $(Kernel-bypass-IPS_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Kernel-bypass-IPS_Link_Flags)
	@echo "LINK =>  $@"

.PHONY: clean

clean:
	@rm -f $(Kernel-bypass-IPS) $(Kernel-bypass-IPS_Cpp_Objects) $(Common_Cpp_Objects)
	@echo "Finish to clear the project"
