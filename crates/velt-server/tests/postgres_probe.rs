use std::net::TcpStream;

use postgresql_embedded::blocking::PostgreSQL;
use postgresql_embedded::Settings;
use tempfile::TempDir;

#[test]
fn embedded_postgres_starts() {
    let data = TempDir::new().unwrap();
    let mut settings = Settings::new();
    settings.data_dir = data.path().to_path_buf();
    settings.port = 0;
    let mut pg = PostgreSQL::new(settings);
    pg.setup().expect("setup postgres");
    pg.start().expect("start postgres");
    let address = format!("{}:{}", pg.settings().host, pg.settings().port);
    println!("postgres at {address}");
    TcpStream::connect(&address).expect("connect to postgres");
    pg.stop().expect("stop postgres");
}
