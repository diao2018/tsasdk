package cn.signdoc;

import cn.signdoc.client.TSAClient;
import cn.signdoc.utils.DigestAlgorithms;
import cn.signdoc.utils.HashUtil;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class TSATest {
    public static void main(String[] arg) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            TSAClient tsClient = new TSAClient();
            tsClient.setTsaURL("http://test1.tsa.cn/tsa");
            tsClient.setTsaUsername("tsademo");
            tsClient.setTsaPassword("tsademo");

            // === SHA-256 Test ===
            System.out.println("========== SHA-256 Test ==========");
            byte[] sha256Hash = HashUtil.getHash("hello tsa", "SHA-256");
            System.out.println("SHA-256 hash (hex): " + bytesToHex(sha256Hash));
            ASN1ObjectIdentifier sha256OID = new ASN1ObjectIdentifier(DigestAlgorithms.getAllowedDigests("SHA-256"));
            byte[] sha256Tsa = tsClient.getTsaAndResp(sha256Hash, sha256OID);
            String sha256Time = tsClient.getTime(sha256Tsa);
            System.out.println("SHA-256 Timestamp: " + sha256Time);
            System.out.println("SHA-256 Token size: " + sha256Tsa.length + " bytes");

            // === SM3 Test ===
            System.out.println("\n========== SM3 Test ==========");
            byte[] sm3Hash = HashUtil.getHash("hello tsa sm3", "SM3");
            System.out.println("SM3 hash (hex): " + bytesToHex(sm3Hash));
            ASN1ObjectIdentifier sm3OID = new ASN1ObjectIdentifier(DigestAlgorithms.getAllowedDigests("SM3"));
            byte[] sm3Tsa = tsClient.getTsaAndResp(sm3Hash, sm3OID);
            String sm3Time = tsClient.getTime(sm3Tsa);
            System.out.println("SM3 Timestamp: " + sm3Time);
            System.out.println("SM3 Token size: " + sm3Tsa.length + " bytes");

            System.out.println("\n========== ALL TESTS PASSED ==========");
        } catch (Exception e) {
            System.out.println("TEST FAILED: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
