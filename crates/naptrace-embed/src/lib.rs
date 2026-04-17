pub mod voyage;
pub mod local;

pub fn has_voyage_key() -> bool {
    std::env::var("VOYAGE_API_KEY").is_ok()
}
