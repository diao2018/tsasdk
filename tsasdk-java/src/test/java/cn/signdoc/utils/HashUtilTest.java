package cn.signdoc.utils;

import org.junit.Assert;
import org.junit.Test;

public class HashUtilTest {
    @Test
    public void computesSha256KnownVector() throws Exception {
        byte[] digest = HashUtil.getHash("abc", "SHA-256");
        Assert.assertEquals(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                bytesToHex(digest));
    }

    @Test
    public void computesSm3KnownVector() throws Exception {
        byte[] digest = HashUtil.getHash("abc", "SM3");
        Assert.assertEquals(
                "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
                bytesToHex(digest));
    }

    @Test
    public void resolvesSm3Oid() {
        Assert.assertEquals("1.2.156.10197.1.401", DigestAlgorithms.getAllowedDigests("SM3"));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
