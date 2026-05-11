const { TSAClient, DigestAlgorithm, computeHash } = require('./src/index');

async function main() {
  try {
    // SHA-256 demo
    console.log('--- SHA-256 Demo ---');
    const client = new TSAClient('http://test1.tsa.cn/tsa', {
      username: 'tsademo',
      password: 'tsademo',
      digestAlgorithm: DigestAlgorithm.SHA256,
    });

    const sha256Hash = computeHash('hello tsa', DigestAlgorithm.SHA256);
    console.log('SHA-256 hash:', sha256Hash.toString('hex'));

    const token = await client.timestampHash(sha256Hash, DigestAlgorithm.SHA256);
    console.log('Token length:', token.length);

    // SM3 demo
    console.log('\n--- SM3 Demo ---');
    const sm3Client = new TSAClient('http://test1.tsa.cn/tsa', {
      username: 'tsademo',
      password: 'tsademo',
      digestAlgorithm: DigestAlgorithm.SM3,
    });

    const sm3Hash = computeHash('hello tsa sm3', DigestAlgorithm.SM3);
    console.log('SM3 hash:', sm3Hash.toString('hex'));

    const sm3Token = await sm3Client.timestampHash(sm3Hash, DigestAlgorithm.SM3);
    console.log('SM3 Token length:', sm3Token.length);
  } catch (e) {
    console.error('Error:', e.message);
  }
}

main();
