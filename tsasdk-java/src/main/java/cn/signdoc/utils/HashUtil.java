/*
 * Unitrust Inc. Copyright (c) 2009 All Rights Reserved.
 */
package cn.signdoc.utils;

import java.security.MessageDigest;
/**
 * @author Rick Diao
 */
public class HashUtil {

	public static byte[] getHash(String strDate,String hashAlgorithms) throws Exception {   
    	byte[] strDateByte = strDate.getBytes();
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
