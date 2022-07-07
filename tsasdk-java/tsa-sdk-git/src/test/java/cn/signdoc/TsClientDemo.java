package cn.signdoc;

import cn.signdoc.client.TSAClient;


import cn.signdoc.utils.DigestAlgorithms;
import cn.signdoc.utils.HashUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;

import java.security.MessageDigest;
import java.security.Security;
/**
 * @author Rick Diao
 */
@Slf4j
public class TsClientDemo {
	public static void main(String[] arg) {
		try {
			Security.addProvider(new BouncyCastleProvider());
			TSAClient tsClient = new TSAClient();
			// add url username password
			tsClient.setTsaURL("http://test1.tsa.cn/tsa");
			tsClient.setTsaUsername("tsademo");
			tsClient.setTsaPassword("tsademo");
			//gen hash
			byte[] hash = HashUtil.getHash("hello tsa", "SHA-256");
			//set digestOID SHA256:2.16.840.1.101.3.4.2.1  SHA512:2.16.840.1.101.3.4.2.2  SM3:1.2.156.10197.1.401
			ASN1ObjectIdentifier digestOID =  new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");
			//get tsa
			byte[] tsa = tsClient.getTsaAndResp(hash, digestOID);
			//print time
			log.info(tsClient.getTime(tsa));
			//print timestamptoken
			log.info(new String(tsa));
		} catch (Exception e) {
			log.info(e.getMessage());
		}
	}

}
