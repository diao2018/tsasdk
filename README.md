## tsasdk

RFC 3161 compliant HTTP client to request timestamps from a trusted timestamp authority (TSA).

Supports **8 programming languages**: Java, PHP, Go, Python, C#, C++, Node.js, Rust.

Includes **SM3 (GB/T 32905-2016)** national cryptographic algorithm support across all language SDKs.

### Supported Languages

| Language | Directory | Hash Algorithms | Package Manager |
|----------|-----------|----------------|-----------------|
| Java | `tsasdk-java/` | SHA-256, SHA-384, SHA-512, SM3 | Maven |
| PHP | `tsasdk-php/` | SHA-256, SHA-384, SHA-512, SM3 | Composer |
| Go | `tsasdk-go/` | SHA-256, SHA-384, SHA-512, SM3 | Go Modules |
| Python | `tsasdk-python/` | SHA-256, SHA-384, SHA-512, SM3 | pip |
| C# | `tsasdk-csharp/` | SHA-256, SHA-384, SHA-512, SM3 | NuGet |
| C++ | `tsasdk-cpp/` | SHA-256, SHA-384, SHA-512, SM3 | CMake |
| Node.js | `tsasdk-nodejs/` | SHA-256, SHA-384, SHA-512, SM3 | npm |
| Rust | `tsasdk-rust/` | SHA-256, SHA-384, SHA-512, SM3 | Cargo |

### Free Timestamp Servers

| Provider | URL |
|----------|-----|
| DigiCert | http://timestamp.digicert.com |
| GlobalSign | http://rfc3161timestamp.globalsign.com/advanced |
| UniTrust | http://test1.tsa.cn/tsa (username: `tsademo`, password: `tsademo`) |
| Entrust | http://timestamp.entrust.net/rfc3161ts2 |
| ComodoCA | http://timestamp.comodoca.com |

### Quick Start

#### Java (JDK 1.8+)

```java
TSAClient tsClient = new TSAClient();
tsClient.setTsaURL("http://test1.tsa.cn/tsa");
tsClient.setTsaUsername("tsademo");
tsClient.setTsaPassword("tsademo");

// SHA-256
byte[] hash = HashUtil.getHash("hello tsa", "SHA-256");
ASN1ObjectIdentifier digestOID = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");
byte[] tsa = tsClient.getTsaAndResp(hash, digestOID);
System.out.println(tsClient.getTime(tsa));

// SM3 (OID: 1.2.156.10197.1.401)
byte[] sm3Hash = HashUtil.getHash("hello tsa", "SM3");
ASN1ObjectIdentifier sm3OID = new ASN1ObjectIdentifier("1.2.156.10197.1.401");
byte[] sm3Tsa = tsClient.getTsaAndResp(sm3Hash, sm3OID);
System.out.println(tsClient.getTime(sm3Tsa));
```

#### Python (3.6+)

```python
from tsasdk import TSAClient, DigestAlgorithm, compute_hash

client = TSAClient("http://test1.tsa.cn/tsa", "tsademo", "tsademo")

# SHA-256
token = client.timestamp(b"hello tsa", DigestAlgorithm.SHA256)

# SM3
sm3_token = client.timestamp(b"hello tsa", DigestAlgorithm.SM3)
```

#### Go

```go
import (
    "github.com/diao2018/tsasdk/tsasdk-go/crypto/digest"
    "github.com/diao2018/tsasdk/tsasdk-go/tsp"
)

// SHA-256
req, _ := tsp.CreateRequest(digest.FromString("hello tsa"))
req.CertReq = true
ts := tsp.GetHttp(nil, "http://test1.tsa.cn/tsa", "tsademo", "tsademo")
resp, _ := ts.Timestamp(context.Background(), req)

// SM3
sm3Req, _ := tsp.CreateRequest(digest.SM3.FromString("hello tsa"))
sm3Resp, _ := ts.Timestamp(context.Background(), sm3Req)
```

#### C# (.NET 6+)

```csharp
using SignDoc.TsaSdk.Tsp;
using SignDoc.TsaSdk.Crypto;

var client = new TSAClient("http://test1.tsa.cn/tsa", "tsademo", "tsademo");

// SHA-256
byte[] token = client.TimestampData(data, DigestAlgorithm.SHA256);

// SM3
byte[] sm3Token = client.TimestampData(data, DigestAlgorithm.SM3);
```

#### Node.js (12+)

```javascript
const { TSAClient, DigestAlgorithm, computeHash } = require('tsasdk');

const client = new TSAClient('http://test1.tsa.cn/tsa', {
  username: 'tsademo', password: 'tsademo'
});

// SHA-256
const token = await client.timestampData('hello tsa', DigestAlgorithm.SHA256);

// SM3
const sm3Token = await client.timestampData('hello tsa', DigestAlgorithm.SM3);
```

#### Rust

```rust
use tsasdk::{TSAClient, DigestAlgorithm, compute_hash};

let client = TSAClient::builder("http://test1.tsa.cn/tsa")
    .username("tsademo").password("tsademo")
    .build();

// SHA-256
let token = client.timestamp_data(b"hello tsa", Some(DigestAlgorithm::SHA256))?;

// SM3
let sm3_token = client.timestamp_data(b"hello tsa", Some(DigestAlgorithm::SM3))?;
```

#### C++ (C++14, OpenSSL 1.1.1+, libcurl)

```cpp
#include "tsasdk/tsa_client.hpp"
#include "tsasdk/hash_util.hpp"

tsasdk::TSAClient client("http://test1.tsa.cn/tsa", "tsademo", "tsademo");

// SHA-256
auto token = client.timestampData(data, len, tsasdk::DigestAlgorithm::SHA256);

// SM3
auto sm3Token = client.timestampData(data, len, tsasdk::DigestAlgorithm::SM3);
```

#### PHP (5.6+)

```php
include_once('TrustedTimestamps.php');

// SHA-256
$sha256 = hash('sha256', 'hello tsa');
$requestFile = TrustedTimestamps::createRequestfile($sha256, 'sha256');
$signature = TrustedTimestamps::signRequestfile($requestFile, $TSA_URL, $username, $password);

// SM3
$sm3 = TrustedTimestamps::hash('hello tsa', 'sm3');
$sm3RequestFile = TrustedTimestamps::createRequestfile($sm3, 'sm3');
$sm3Signature = TrustedTimestamps::signRequestfile($sm3RequestFile, $TSA_URL, $username, $password);
```

### Digest Algorithm OIDs

| Algorithm | OID |
|-----------|-----|
| SHA-256 | 2.16.840.1.101.3.4.2.1 |
| SHA-384 | 2.16.840.1.101.3.4.2.2 |
| SHA-512 | 2.16.840.1.101.3.4.2.3 |
| SM3 | 1.2.156.10197.1.401 |

### Contact

* email: rickxy@qq.com
