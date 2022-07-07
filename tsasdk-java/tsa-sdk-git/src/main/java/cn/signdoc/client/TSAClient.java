package cn.signdoc.client;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.Security;
import java.text.SimpleDateFormat;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.*;
import org.bouncycastle.util.encoders.Base64;

/**
 * @author Rick Diao
 */
@Slf4j
public class TSAClient {

	private String tsaURL;
	private String tsaUsername;
	private String tsaPassword;
	private int ConnectTimeout = 8000;

	public void setTsaURL(String tsaURL) {
		this.tsaURL = tsaURL;
	}
	public void setTsaUsername(String tsaUsername) {
		this.tsaUsername = tsaUsername;
	}
	public void setTsaPassword(String tsaPassword) {
		this.tsaPassword = tsaPassword;
	}
	public void setConnectTimeout(int connectTimeout) {
		ConnectTimeout = connectTimeout;
	}

	/**
	 * get time
	 * @param tsaToken
	 * @return String
	 * @throws Exception
	 */
	public String getTime(byte[] tsaToken) throws Exception {
		try {
			Security.addProvider(new BouncyCastleProvider());
			CMSSignedData csd = new CMSSignedData(tsaToken);
			TimeStampToken timeStampToken = new TimeStampToken(csd);
			SimpleDateFormat dateFm = new SimpleDateFormat(
					"yyyy-MM-dd HH:mm:ss");
			String tsaStrTime = dateFm.format(timeStampToken.getTimeStampInfo()
					.getGenTime());
			return tsaStrTime;
		} catch (Exception e) {
			throw e;
		}
	}

	/**
	 * get tsa
	 * @param hashCode
	 * @return byte[]
	 * @throws Exception
	 */
	public byte[] getTsaAndResp(byte[] hashCode, ASN1ObjectIdentifier hashOID)
			throws Exception {
		byte[] tsa = null;
		try {
			if(this.tsaURL == null && this.tsaUsername == null && this.tsaPassword == null){
				throw new Exception("timestamp account is null");
			}else{
				Security.addProvider(new BouncyCastleProvider());
				TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
				tsqGenerator.setCertReq(true);
				BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
				TimeStampRequest request = tsqGenerator.generate(hashOID, hashCode, nonce);
				byte[] requestBytes = request.getEncoded();
				byte[] respBytes = getTSAResponse(requestBytes);

				TimeStampResponse response = new TimeStampResponse(respBytes);
				PKIFailureInfo failure = response.getFailInfo();
				int value = (failure == null) ? 0 : failure.intValue();
				if (value != 0)
					throw new Exception("Invalid TSA '" + tsaURL + "' response, code " + value);
				TimeStampToken tsaToken = response.getTimeStampToken();
				if (tsaToken == null)
					throw new Exception("TSA '" + tsaURL + "' failed to return time stamp token");
				tsa = tsaToken.getEncoded();
			}
			return tsa;
		} catch (Exception e) {
			throw e;
		} catch (Throwable t) {
			throw new Exception("Failed to get TSA response from '" + tsaURL
					+ "'", t);
		}
	}

	protected byte[] getTSAResponse(byte[] requestBytes) throws Exception {
		URL url = new URL(tsaURL);
		URLConnection tsaConnection = (URLConnection) url.openConnection();
		tsaConnection.setDoInput(true);
		tsaConnection.setDoOutput(true);
		tsaConnection.setUseCaches(false);
		tsaConnection.setConnectTimeout(this.ConnectTimeout);
		tsaConnection.setRequestProperty("Content-Type",
				"application/timestamp-query");
		tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");
		if ((tsaUsername != null) && !tsaUsername.equals("")) {
			String userPassword = tsaUsername + ":" + tsaPassword;
			tsaConnection.setRequestProperty("Authorization", "Basic "
					+ new String(new sun.misc.BASE64Encoder()
							.encode(userPassword.getBytes())));
		}
		OutputStream out = tsaConnection.getOutputStream();
		out.write(requestBytes);
		out.close();
		InputStream inp = tsaConnection.getInputStream();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024];
		int bytesRead = 0;
		while ((bytesRead = inp.read(buffer, 0, buffer.length)) >= 0) {
			baos.write(buffer, 0, bytesRead);
		}
		byte[] respBytes = baos.toByteArray();
		String encoding = tsaConnection.getContentEncoding();
		
		if (encoding != null && encoding.equalsIgnoreCase("base64")) {
			respBytes = Base64.decode(new String(respBytes));
		}
		return respBytes;
	}

}