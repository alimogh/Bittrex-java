
import java.util.Date;
import java.util.Formatter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.sql.Timestamp;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class Bittrex {
	private static final String HMAC_SHA512 = "HmacSHA512";
	public static void main(String args[]) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException {
		String result =getBalances();
		System.out.println(result);
		
	}
	
	private static String getBalances() throws IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		URL url = new URL("https://api.bittrex.com/v3/balances");
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		HttpURLConnection connection = getHeaders(con);
		connection.setRequestMethod("GET");
		int status = connection.getResponseCode();
		System.out.println(status);
		System.out.println(connection.getResponseMessage());
		BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
		String inputLine;
		StringBuffer content = new StringBuffer();
		while ((inputLine = in.readLine()) != null) {
				    content.append(inputLine);
				}
		in.close();
		connection.disconnect();
		return content.toString();
	}

	private static HttpURLConnection getHeaders(HttpURLConnection con) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		String timestamp =getTimestamp();
		String contentHash = getContentHash("");
		String uri ="https://api.bittrex.com/v3/balances";
		String method ="GET";
		String apiSecret = "";
		String preSignature = getPresignature(timestamp, uri, method, contentHash);
		String signature = getSignature(preSignature,apiSecret);
		con.setRequestProperty("Api-Key", "");
		con.setRequestProperty("Api-Timestamp", timestamp);
		con.setRequestProperty("Api-Content-Hash", contentHash);
		con.setRequestProperty("Api-Signature", signature);
		return con;
		
	}

	private static String getSignature(String preSignature, String apiSecret) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException{
		SecretKeySpec secretKeySpec = new SecretKeySpec(apiSecret.getBytes(), HMAC_SHA512);
	    Mac mac = Mac.getInstance(HMAC_SHA512);
	    mac.init(secretKeySpec);
	    return toHexString(mac.doFinal(preSignature.getBytes()));
	}

	private static String toHexString(byte[] bytes) {
		Formatter formatter = new Formatter();
	    for (byte b : bytes) {
	        formatter.format("%02x", b);
	    }
	    return formatter.toString();
	}

	private static String getPresignature(String timestamp, String uri, String method, String contentHash) {
		String preSig = String.join("", timestamp, uri, method, contentHash); 
		return preSig;
	}
	private static String getTimestamp() {
		Date date= new Date();
		String time = Long.toString(date.getTime());
		return time;
	}
	
	public static String getContentHash(String input) 
	{ 
		try { 
			// getInstance() method is called with algorithm SHA-512 
			MessageDigest md = MessageDigest.getInstance("SHA-512"); 

			// digest() method is called 
			// to calculate message digest of the input string 
			// returned as array of byte 
			byte[] messageDigest = md.digest(input.getBytes()); 

			// Convert byte array into signum representation 
			BigInteger no = new BigInteger(1, messageDigest); 

			// Convert message digest into hex value 
			String hashtext = no.toString(16); 

			// Add preceding 0s to make it 32 bit 
			while (hashtext.length() < 32) { 
				hashtext = "0" + hashtext; 
			} 

			// return the HashText 
			return hashtext; 
		} 

		// For specifying wrong message digest algorithms 
		catch (NoSuchAlgorithmException e) { 
			throw new RuntimeException(e); 
		} 
	} 

}
