RUSTC ?= rustc
RUSTFLAGS ?=

RUST_SRC=$(shell find . -type f -name '*.rs')

libmaxminddb_so=build/.libhttp.timestamp

$(libmaxminddb_so): src/maxminddb/lib.rs $(RUST_SRC)
	mkdir -p build/
	$(RUSTC) $(RUSTFLAGS) $< --out-dir=build
	touch $@

.PHONY: all
all:   $(libmaxminddb_so)

build/maxminddb-test: src/maxminddb/lib.rs $(RUST_SRC)
	mkdir -p build/
	$(RUSTC) $(RUSTFLAGS) $< -o $@ --test

.PHONY: check
check: build/maxminddb-test
	./build/maxminddb-test $(TEST)

.PHONY: clean
clean:
	rm -fr build
