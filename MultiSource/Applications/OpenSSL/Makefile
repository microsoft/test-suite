# MultiSource/OpenSSL Makefile

LEVEL = ../../..
PROG = OpenSSL
LDFLAGS = -lm

include $(LEVEL)/Makefile.config

EXTRA_TEST_RESULTS_FILE := $(PROJ_OBJ_DIR)/Output/OpenSSL.extra-results.txt
RUN_OPTIONS := $(EXTRA_TEST_RESULTS_FILE)

include ../../Makefile.multisrc

