# Change Log #

## 0.13.0 - 2019-01-21

* Missing models for `DensityIncome`, `Domain`, and `Asn` were added
  and the missing `is_in_european_union` field was added to the
  `Country` model. Pull request by Sebastian Nadorp. GitHub #19.
* More details are now included in the `Display` implementation for
  `MaxMindDBError`. Pull request by Mike Cooper. GitHub #20.

## 0.12.0 - 2018-12-09

* `Reader::open` has been removed. You should use `Reader::open_readfile`
  or `Reader::open_mmap`. Pull request by kpcyrd. GitHub #17 & #18.
* `Reader::open_readfile` no longer depends on `unsafe`. Pull request by
  kpcyrd. GitHub #17 & #18.

## 0.11.0 - 2018-11-12

* An optional `mmap` cfg feature flag has been added. When set, `open`
  will use the `memmap` crate to memory map the database file rather
  than reading it from file. In addition to `open`, `open_readfile`
  and `open_mmap` are available. PR by moschroe. GitHub #16.
* `Reader::open` now takes an `AsRef<Path>`. Also, #16.
* `Reader::from_buf` allows using an existing buffer instead of
  specifying a database file. PR by kpcyrd. GitHub #15.

## 0.10.0 - 2018-08-07

* Derive `Serialize` for GeoIP2 models. Pull request by Bryan Gilbert.
  GitHub #11.

## 0.9.0 - 2018-02-16

* Update logger to 0.4 and env_logger to 0.5.

## 0.8.1 - 2017-07-02

* Implement unimplemented deserialize methods.

## 0.8.0 - 2017-06-28

* API CHANGE: Switch to Serde for deserialization. Data structures being
  deserialized to must implement the `Deserialize` trait. Pull request by
  Wesley Moore. GitHub #5.

## 0.7.2 - 2017-04-16

* Update `log` to 0.3.7 and `rustc-serialize` to 0.3.23.

## 0.7.1 - 2016-11-13

* Update `rustc-serialize` to 0.3.21.

## 0.7.0 - 2016-05-15

* API CHANGE: `lookup` takes an `IpAddr` again instead of a `SocketAddr`. We
  previously switched to `SocketAddr` after `IpAddr` had been deprecated, but
  it has since been re-added.
