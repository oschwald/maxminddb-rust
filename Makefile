CARGO ?= cargo
RUSTC ?= rustc

libgeoip2_so=target/.libgeoip2.timestamp

libmaxminddb_so=target/.libmaxminddb.timestamp

.PHONY: all
all:   $(libmaxminddb_so) examples

$(libmaxminddb_so): src/maxminddb/lib.rs src/maxminddb/geoip2.rs src/maxminddb/decoder.rs
	$(CARGO) build
	touch $@

target/lookup: example/lookup.rs $(libmaxminddb_so)
	mkdir -p build
	$(RUSTC) $(RUSTFLAGS) $< -o $@ -L target/debug -L target/debug/deps/

examples: target/lookup

.PHONY: check
check:
	$(CARGO) build --features "dev"
	$(CARGO) test

.PHONY: clean
clean:
	rm -fr target
