GO ?= go
RM ?= rm
SCDOC ?= scdoc
MANDOC ?= mandoc
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

# HTML man pages for GitHub Pages (docs/), mirroring soju.im/doc/soju.1.html.
# Requires mandoc; not part of `all` since it's docs infra, not a build artifact.
html: docs/sake.1.html docs/sakectl.1.html
docs/sake.1.html: doc/sake.1.scd doc/man-style.css
	mkdir -p docs
	$(SCDOC) <doc/sake.1.scd | $(MANDOC) -T html -O style=man-style.css | \
		sed -E 's,<b>(sake|sakectl)</b>\(1\),<a href="\1.1.html"><b>\1</b>(1)</a>,g' \
		>docs/sake.1.html
	cp -f doc/man-style.css docs/man-style.css
docs/sakectl.1.html: doc/sakectl.1.scd doc/man-style.css
	mkdir -p docs
	$(SCDOC) <doc/sakectl.1.scd | $(MANDOC) -T html -O style=man-style.css | \
		sed -E 's,<b>(sake|sakectl)</b>\(1\),<a href="\1.1.html"><b>\1</b>(1)</a>,g' \
		>docs/sakectl.1.html
	cp -f doc/man-style.css docs/man-style.css

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

.PHONY: sake sakedb sakectl html clean install
