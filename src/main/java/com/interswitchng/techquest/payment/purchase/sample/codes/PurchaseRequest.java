package com.interswitchng.techquest.payment.purchase.sample.codes;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.JSONException;
import org.json.JSONObject;

import com.interswitchng.techquest.payment.purchase.sample.codes.utils.OAuth;
import com.interswitchng.techquest.payment.purchase.sample.codes.utils.SecureDecryptor;
import com.interswitchng.techquest.system.service.util.api.SystemConstantsApi;

import hsmprobe.util.Base64;

public class PurchaseRequest {

	public static final String BASE_URL = "http://sandbox.interswitchng.com/api/v1/payment/purchases";
	public static final String BASE_URL2 = "https://sandbox.interswitchng.com/api/v1/payment/purchases";

	private static final String TIMESTAMP = "TIMESTAMP";
	private static final String NONCE = "NONCE";
	private static final String SIGNATURE_METHOD = "SIGNATURE_METHOD";
	private static final String SIGNATURE = "SIGNATURE";
	private static final String AUTHORIZATION = "AUTHORIZATION";

	private static final String CLIENT_ID = "CLIENT_ID";
	private static final String CLIENT_SECRET = "CLIENT_SECRET";
	
	public static void main(String[] args) throws Exception {
		purchaseRequest();
	}

	public static String getAuthData(String pin, String pan, String expiryDate, 
			String cvv2, String version, String otpIdentifier)
	{
		String authData = pan + "D" + pin + "D" + expiryDate + "D" + cvv2 + "D" + version + "D" + otpIdentifier;
		String encryptedAuthDataBase64 = null;
		
		try
		{
			String modulus = "9c7b3ba621a26c4b02f48cfc07ef6ee0aed8e12b4bd11c5cc0abf80d5206be69e1891e60fc88e2d565e2fabe4d0cf630e318a6c721c3ded718d0c530cdf050387ad0a30a336899bbda877d0ec7c7c3ffe693988bfae0ffbab71b25468c7814924f022cb5fda36e0d2c30a7161fa1c6fb5fbd7d05adbef7e68d48f8b6c5f511827c4b1c5ed15b6f20555affc4d0857ef7ab2b5c18ba22bea5d3a79bd1834badb5878d8c7a4b19da20c1f62340b1f7fbf01d2f2e97c9714a9df376ac0ea58072b2b77aeb7872b54a89667519de44d0fc73540beeaec4cb778a45eebfbefe2d817a8a8319b2bc6d9fa714f5289ec7c0dbc43496d71cf2a642cb679b0fc4072fd2cf";
			String privateExponent = "4913cc0183c7a4a74b5405db55a15db8942f38c8cd7974b3644f6b625d22451e917345baa9750be9f8d10da47dbb45e602c86a6aa8bc1e7f7959561dbaaf35e78a8391009c8d86ee11da206f1ca190491bd765f04953765a2e55010d776044cb2716aee6b6f2f1dc38fce7ab0f4eafec8903a73555b4cf74de1a6bfc7f6a39a869838e3678dcbb96709068358621abf988e8049d5c07d128c5803e9502c05c3e38f94658480621a3e1c75fb4e39773e6eec50f5ef62958df864874ef0b00a0fb86f8382d1657381bc3c283567927f1f68d60205fd7ca1197265dd85c173badc1a15044f782602a9e14adc56728929c646c24fe8e10d26afc733158841d9ed4d1";
			String publicExponent = "010001";

			SystemConstantsApi systemConstantsApi = null;
			SecureDecryptor secureDecryptor = SecureDecryptor.getInstance(systemConstantsApi, modulus, privateExponent, publicExponent);
			
			byte []encryptedAuthDataBytes = secureDecryptor.encrypt(authData, systemConstantsApi);
			
			encryptedAuthDataBase64 = Base64.encodeBytes(encryptedAuthDataBytes).replaceAll("\\r|\\n", "");
			
			System.out.println("AuthData: " + authData);
			System.out.println("Encrypted AuthData: " + encryptedAuthDataBase64);
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
		
		return encryptedAuthDataBase64;
	}
	
	public static void purchaseRequest() throws NoSuchAlgorithmException,
			ClientProtocolException, IOException, JSONException {

		String customerId = "tunjiadaora@gmail.com";
		
		String amount = "100.00";
		
		String authData = getAuthData("1234", "1234123412341234123", "1234", "123", "", "");
		
		String currency = "NGN";
		
		String paymentReference = "24000";
		
		String requestorId = "11179920172";
		
		// Authentication is done via a POST Method.
		String httpMethod = "POST";

		// This is the request resource URL.
		String resourceUrl = BASE_URL;
		String resourceUrl2 = BASE_URL2;

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
		HashMap<String, String> oAuth = OAuth
				.generateOAuth(httpMethod, resourceUrl2, clientId,
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

		// Printout response code
		System.out.println(responseCode);
		System.out.println();

		// Printout response string
		System.out.println(responseString);
		System.out.println();

		// Printout response string
		System.out.println("Url: " + resourceUrl);
		System.out.println("Authorization: "
				+ oAuth.get(AUTHORIZATION));
		System.out.println("Timestamp: " + oAuth.get(TIMESTAMP));
		System.out.println("Nonce: " + oAuth.get(NONCE));
		System.out.println("Signature: " + oAuth.get(SIGNATURE));
		System.out.println("SignatureMethod: "
				+ oAuth.get(SIGNATURE_METHOD));
	}

}
