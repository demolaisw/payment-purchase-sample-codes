package com.interswitchng.techquest.payment.purchase.sample.codes;

import java.io.InputStream;
import java.io.StringWriter;
import java.util.HashMap;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.JSONObject;

import com.interswitchng.techquest.payment.purchase.sample.codes.utils.OAuth;

public class AuthorizeOTPRequest {

	public static final String BASE_URL = "http://sandbox.interswitchng.com/api/v1/payment/otps/auths";

	private static final String TIMESTAMP = "TIMESTAMP";
	private static final String NONCE = "NONCE";
	private static final String SIGNATURE_METHOD = "SIGNATURE_METHOD";
	private static final String SIGNATURE = "SIGNATURE";
	private static final String AUTHORIZATION = "AUTHORIZATION";
	private static final String CLIENT_ID = "CLIENT_ID";
	private static final String CLIENT_SECRET = "CLIENT_SECRET";
	
	public static void main(String[] args) throws Exception {
		authorizeOTPRequest();
	}

	public static void authorizeOTPRequest() throws Exception 
	{
		String otpTransactionIdentifier = "fXMUcnmydau34YEQdAHGN7lIWsZLnnEaiNeMpDGYAUSev7sfUwbWCPY5jdVPu55zjQhucxFi8XMmiuuy";
		String otp = "909631";

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
		String signatureMethod = "SHA-256";
		// JSONObject is used to properly generate json string for the request
		// body.
		JSONObject json = new JSONObject();	
		json.put("otpTransactionIdentifier", otpTransactionIdentifier);
		json.put("otp", otp);

		StringWriter out = new StringWriter();
		json.write(out);
		String data = out.toString();
		
		String additionalParameters = ((otpTransactionIdentifier == null || otpTransactionIdentifier.isEmpty()) ? "" : ("&" + otpTransactionIdentifier))
				+ ((otp == null || otp.isEmpty()) ? "" : ("&" + otp));

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
