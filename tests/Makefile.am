check_SCRIPTS =
TESTS = $(check_SCRIPTS)

check_SCRIPTS += ima_hash.test sign_verify.test boot_aggregate.test

check_PROGRAMS = \
	create_ima_signature

create_ima_signature_CFLAGS = -I$(top_srcdir)/src
create_ima_signature_LDFLAGS = -lcrypto -L$(top_builddir)/src/.libs -limaevm

clean-local:
	-rm -f *.txt *.out *.sig *.sig2

distclean: distclean-keys
.PHONY: distclean-keys
distclean-keys:
	./gen-keys.sh clean
