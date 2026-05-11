/*
 * Unitrust Inc. Copyright (c) 2009 All Rights Reserved.
 */
package cn.signdoc.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
/**
 * @author Rick Diao
 */
public class HashUtil {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

	public static byte[] getHash(String strDate,String hashAlgorithms) throws Exception {
        byte[] strDateByte = strDate.getBytes(StandardCharsets.UTF_8);
        MessageDigest md = MessageDigest.getInstance(hashAlgorithms);
        md.update(strDateByte, 0, strDateByte.length);
        return md.digest();
    }  

	public static byte[] getHash(byte[] strDate,String hashAlgorithms) throws Exception {   
    	MessageDigest md = MessageDigest.getInstance(hashAlgorithms);  
        md.update(strDate, 0, strDate.length);
        return md.digest(); 
    }  
}
