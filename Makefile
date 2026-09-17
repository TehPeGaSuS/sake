GO ?= go
RM ?= rm
SCDOC ?= scdoc
GOFLAGS ?=
PREFIX ?= /usr/local
BINDIR ?= bin
MANDIR ?= share/man
SYSCONFDIR ?= /etc
RUNDIR ?= /run

sharedstatedir := /var/lib
config_path := $(SYSCONFDIR)/sake/config
admin_socket_path := $(RUNDIR)/sake/admin
goldflags := -X 'github.com/TehPeGaSuS/sake/config.DefaultPath=$(config_path)' \
	-X 'github.com/TehPeGaSuS/sake/config.DefaultUnixAdminPath=$(admin_socket_path)'
goflags := $(GOFLAGS) -ldflags="$(goldflags)"
commands := sake sakectl sakedb
man_pages := doc/sake.1 doc/sakectl.1

all: $(commands) $(man_pages)

sake:
	$(GO) build $(goflags) -o . ./cmd/sake ./cmd/sakedb ./cmd/sakectl
sakedb sakectl: sake
doc/sake.1: doc/sake.1.scd
	$(SCDOC) <doc/sake.1.scd >doc/sake.1
doc/sakectl.1: doc/sakectl.1.scd
	$(SCDOC) <doc/sakectl.1.scd >doc/sakectl.1

clean:
	$(RM) -f $(commands) $(man_pages)
install:
	mkdir -p $(DESTDIR)$(PREFIX)/$(BINDIR)
	mkdir -p $(DESTDIR)$(PREFIX)/$(MANDIR)/man1
	mkdir -p $(DESTDIR)$(SYSCONFDIR)/sake
	mkdir -p $(DESTDIR)$(sharedstatedir)/sake
	cp -f $(commands) $(DESTDIR)$(PREFIX)/$(BINDIR)
	cp -f $(man_pages) $(DESTDIR)$(PREFIX)/$(MANDIR)/man1
	[ -f $(DESTDIR)$(config_path) ] || cp -f config.in $(DESTDIR)$(config_path)
	if go version -m sake | grep -E '^\s*build\s*-tags=' | grep -Eq '(=|,)pam($|,)'; then \
	  mkdir -p $(DESTDIR)$(SYSCONFDIR)/pam.d; \
	  cp -f auth/pam_config $(DESTDIR)$(SYSCONFDIR)/pam.d/sake; \
	fi

.PHONY: sake sakedb sakectl clean install
