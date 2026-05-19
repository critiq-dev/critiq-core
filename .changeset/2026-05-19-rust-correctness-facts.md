---
"@critiq/adapter-rust": minor
"@critiq/adapter-shared": minor
---

Add Rust correctness adapter facts for mutex guards held across `.await`, blocking sleep and `block_on` inside `async fn`, forgotten join handles, unbounded channels, `std::sync::Mutex` in async functions, and unchecked slice indexing with variable indices.
