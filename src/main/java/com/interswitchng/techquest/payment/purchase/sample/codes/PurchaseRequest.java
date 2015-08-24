package com.interswitchng.techquest.payment.purchase.sample.codes;

import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;

import com.interswitchng.techquest.payment.purchase.sample.codes.utils.OAuth;

public class PurchaseRequest {

	public static final String BASE_URL = "http://sandbox.interswitchng.com/api/v1/payment/purchases";

	private static final String TIMESTAMP = "TIMESTAMP";
	private static final String NONCE = "NONCE";
	private static final String SIGNATURE_METHOD = "SIGNATURE_METHOD";
	private static final String SIGNATURE = "SIGNATURE";
	private static final String AUTHORIZATION = "AUTHORIZATION";
	private static final String CLIENT_ID = "CLIENT_ID";
	private static final String CLIENT_SECRET = "CLIENT_SECRET";
	private static final String modulus = "9c7b3ba621a26c4b02f48cfc07ef6ee0aed8e12b4bd11c5cc0abf80d5206be69e1891e60fc88e2d565e2fabe4d0cf630e318a6c721c3ded718d0c530cdf050387ad0a30a336899bbda877d0ec7c7c3ffe693988bfae0ffbab71b25468c7814924f022cb5fda36e0d2c30a7161fa1c6fb5fbd7d05adbef7e68d48f8b6c5f511827c4b1c5ed15b6f20555affc4d0857ef7ab2b5c18ba22bea5d3a79bd1834badb5878d8c7a4b19da20c1f62340b1f7fbf01d2f2e97c9714a9df376ac0ea58072b2b77aeb7872b54a89667519de44d0fc73540beeaec4cb778a45eebfbefe2d817a8a8319b2bc6d9fa714f5289ec7c0dbc43496d71cf2a642cb679b0fc4072fd2cf";
	private static final String publicExponent = "010001";
	
	public static void main(String[] args) throws Exception {
		purchaseRequest();
	}

	public static void purchaseRequest() throws Exception 
	{
		String customerId = "tunjiadaora@gmail.com";		
		String amount = "100.00";
		String currency = "NGN";		
		String paymentReference = "24007";		
		String requestorId = "11179920172";
		String version = "1";
		
		// AuthDataTextCipher -> AuthData
		String pan = "627629020217176055";
		String pin = "1111";
		String expiryDate = "1612";
		String cvv2 = "111";
		String authDataTextCipher = version + "D" + pan + "D" + pin + "D" + expiryDate + "D" + cvv2;
		
		Cipher encryptCipher = null;
		Security.addProvider(new BouncyCastleProvider());
		KeyFactory factory = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec publicKeyspec = new RSAPublicKeySpec(new BigInteger(modulus, 16), new BigInteger(publicExponent, 16));
		PublicKey publicKey = factory.generatePublic(publicKeyspec);
		encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);	
		byte []encryptedAuthDataBytes = encryptCipher.doFinal(authDataTextCipher.getBytes("UTF8"));
		String authData = Base64.encodeBase64String(encryptedAuthDataBytes).replaceAll("\\r|\\n", "");

		// Authentication is done via a POST Method.
		String httpMethod = "POST";
		// This is the request resource URL.
		String resourceUrl = BASE_URL;
		// get clientId from Interswitch Developer Console.
		String clientId = CLIENT_ID;
		// get clientSecretKey from Interswitch Developer Console
		String clientSecretKey = CLIENT_SECRET;
		// Signature Method is the discretion of developer,
		// but we recommend at least SHA-256
		String signatureMethod = "SHA1";
		// JSONObject is used to properly generate json string for the request
		// body.
		JSONObject json = new JSONObject();		
		json.put("customerId", customerId);		
		json.put("amount", amount);		
		json.put("authData", authData);		
		json.put("currency", currency);		
		json.put("paymentReference", paymentReference);		
		json.put("requestorId", requestorId);
		StringWriter out = new StringWriter();
		json.write(out);
		String data = out.toString();
		
		String additionalParameters = ((customerId == null || customerId.isEmpty()) ? "" : ("&" + customerId))
				+ ((amount == null || amount.isEmpty()) ? "" : ("&" + amount))
				+ ((authData == null || authData.isEmpty()) ? "" : ("&" + authData))
				+ ((currency == null || currency.isEmpty()) ? "" : ("&" + currency))
				+ ((paymentReference == null || paymentReference.isEmpty()) ? "" : ("&" + paymentReference));

		additionalParameters = additionalParameters.substring(1,
				additionalParameters.length());
		

		// This our Authorization details that we'll add to our headers,
		// the InterswitchAuth configuration can be found under Authentications
		// above.
		HashMap<String, String> oAuth = OAuth.generateOAuth(httpMethod, resourceUrl, clientId,
						clientSecretKey, additionalParameters, signatureMethod);

		// Write HTTP request to post
		HttpClient client = new DefaultHttpClient();
		HttpPost post = new HttpPost(resourceUrl);

		// Set headers for authorization
		post.setHeader("Authorization", oAuth.get(AUTHORIZATION));
		post.setHeader("Timestamp", oAuth.get(TIMESTAMP));
		post.setHeader("Nonce", oAuth.get(NONCE));
		post.setHeader("Signature", oAuth.get(SIGNATURE));
		post.setHeader("SignatureMethod", oAuth.get(SIGNATURE_METHOD));

		StringEntity entity = new StringEntity(data);

		entity.setContentType("application/json");

		// attach json to body of request
		post.setEntity(entity);

		// post
		HttpResponse response = client.execute(post);

		// Get response Code
		int responseCode = response.getStatusLine().getStatusCode();

		// get response string
		HttpEntity httpEntity = response.getEntity();
		InputStream inputStream = httpEntity.getContent();
		StringBuffer responseString = new StringBuffer();

		int c;
		// Reading Response from server
		while ((c = inputStream.read()) != -1) {
			responseString.append((char) c);
		}
	}

}
