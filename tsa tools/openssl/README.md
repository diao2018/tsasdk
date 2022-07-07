### Create TimeStampRequest
 * Create a tsq (TimeStampRequest) file, which contains a hash of the file you want to sign.
 * $ openssl ts -query -data file.png -no_nonce -sha512 -cert -out file.tsq
### Send TimeStampRequest
 * Send the TimeStampRequest to freeTSA.org and receive a tsr (TimeStampResponse) file.
 * $ curl -H "Content-Type: application/timestamp-query" --data-binary '@file.tsq' https://tsademo:tsademo@test1.tsa.cn/tsa > file.tsr
### verify timestamp
 * With the public Certificates you can verify the TimeStampRequest.
 * $ openssl ts -verify -in file.tsr -queryfile file.tsq -CAfile cacert.pem -untrusted tsa.crt