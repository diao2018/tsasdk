use tsasdk::{compute_hash, DigestAlgorithm, TSAClient};

fn main() {
    // SHA-256 demo
    println!("--- SHA-256 Demo ---");
    let client = TSAClient::builder("http://test1.tsa.cn/tsa")
        .username("tsademo")
        .password("tsademo")
        .default_algorithm(DigestAlgorithm::SHA256)
        .build();

    let sha256_hash = compute_hash("hello tsa", DigestAlgorithm::SHA256);
    println!("SHA-256 hash: {}", hex::encode(&sha256_hash));

    match client.timestamp_hash(&sha256_hash, Some(DigestAlgorithm::SHA256)) {
        Ok(token) => println!("Token length: {}", token.len()),
        Err(e) => println!("Error: {}", e),
    }

    // SM3 demo
    println!("\n--- SM3 Demo ---");
    let sm3_client = TSAClient::builder("http://test1.tsa.cn/tsa")
        .username("tsademo")
        .password("tsademo")
        .default_algorithm(DigestAlgorithm::SM3)
        .build();

    let sm3_hash = compute_hash("hello tsa sm3", DigestAlgorithm::SM3);
    println!("SM3 hash: {}", hex::encode(&sm3_hash));

    match sm3_client.timestamp_hash(&sm3_hash, Some(DigestAlgorithm::SM3)) {
        Ok(token) => println!("SM3 Token length: {}", token.len()),
        Err(e) => println!("Error: {}", e),
    }
}
