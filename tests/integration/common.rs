use maxminddb::Reader;

pub(crate) const TEST_DATABASE_CONFIGS: &[(usize, usize)] =
    &[(24, 4), (28, 4), (32, 4), (24, 6), (28, 6), (32, 6)];
pub(crate) const TEST_RECORD_SIZES: &[usize] = &[24, 28, 32];

pub(crate) fn open_test_data_reader(database: &str) -> Reader<Vec<u8>> {
    Reader::open_readfile(format!("test-data/test-data/{database}"))
        .unwrap_or_else(|e| panic!("failed to open test database '{database}': {e}"))
}
