RUSTC ?= rustc
RUSTFLAGS ?=

RUST_SRC=$(shell find . -type f -name '*.rs')

libgeoip2_so=build/.libgeoip2.timestamp

libmaxminddb_so=build/.libmaxminddb.timestamp

.PHONY: all
all:   $(libmaxminddb_so) $(libgeoip2_so) examples

$(libmaxminddb_so): src/maxminddb/lib.rs $(RUST_SRC)
	mkdir -p build/
	$(RUSTC) $(RUSTFLAGS) $< --out-dir=build
	touch $@

$(libgeoip2_so): src/geoip2/lib.rs $(RUST_SRC) $(libmaxminddb_so)
	mkdir -p build/
	$(RUSTC) $(RUSTFLAGS) $< --out-dir=build -L build
	touch $@

build/maxminddb-test: src/maxminddb/lib.rs $(RUST_SRC)
	mkdir -p build/
	$(RUSTC) $(RUSTFLAGS) $< -o $@ --test

build/lookup: example/lookup.rs $(libmaxminddb_so) $(libgeoip2_so)
	mkdir -p build
	$(RUSTC) $(RUSTFLAGS) $< -o $@ -L build/

examples: build/lookup

.PHONY: check
check: build/maxminddb-test
	./build/maxminddb-test $(TEST)

.PHONY: clean
clean:
	rm -fr build
