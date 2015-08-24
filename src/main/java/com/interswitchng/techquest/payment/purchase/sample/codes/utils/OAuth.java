package com.interswitchng.techquest.payment.purchase.sample.codes.utils;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.TimeZone;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.json.simple.parser.JSONParser;

public class OAuth {

	private static final String CUSTOM_OAUTH_TOKEN_RESOURCE_URL = "http://sandbox.interswitchng.com/passport/oauth/token";
	
	private static final String TIMESTAMP = "TIMESTAMP";
	private static final String NONCE = "NONCE";
	private static final String SIGNATURE_METHOD = "SIGNATURE_METHOD";
	private static final String SIGNATURE = "SIGNATURE";
	private static final String AUTHORIZATION = "AUTHORIZATION";

	private static final String AUTHORIZATION_REALM = "Bearer ";
	private static final String ISO_8859_1 = "ISO-8859-1";

	public static HashMap<String, String> generateOAuth(
			String httpMethod, String resourceUrl, String clientId,
			String clientSecretKey, String additionalParameters,
			String signatureMethod) throws UnsupportedEncodingException,
			NoSuchAlgorithmException {
		HashMap<String, String> oAuth = new HashMap<String, String>();
		
		//Timezone MUST be Africa/Lagos.
		TimeZone lagosTimeZone = TimeZone.getTimeZone("Africa/Lagos");

		Calendar calendar = Calendar.getInstance(lagosTimeZone);
		
		// Timestamp must be in seconds.
		long timestamp = calendar.getTimeInMillis() / 1000;

		UUID uuid = UUID.randomUUID();
		String nonce = uuid.toString().replaceAll("-", "");

		// Token Request
		org.json.simple.JSONObject jsonResponse = null;
		
		try {
			String clientCipher = clientId + ":" + clientSecretKey;
			String clientBase64 = new String(Base64.encodeBase64(clientCipher
					.getBytes()));
			String authorization = "Basic " + clientBase64;
			
			ArrayList<NameValuePair> postParameters = new ArrayList<NameValuePair>();
			postParameters.add(new BasicNameValuePair("grant_type", "client_credentials"));
			postParameters.add(new BasicNameValuePair("scope", "profile"));
			
			HttpClient client = new DefaultHttpClient();
			HttpPost post = new HttpPost(CUSTOM_OAUTH_TOKEN_RESOURCE_URL);
			post.setHeader("Authorization", authorization);
			post.setEntity(new UrlEncodedFormEntity(postParameters));
			HttpResponse response = client.execute(post);
			HttpEntity httpEntity = response.getEntity();
			InputStream inputStream = httpEntity.getContent();
			StringBuffer responseString = new StringBuffer();

			int c;
			// Read response
			while ((c = inputStream.read()) != -1) {
				responseString.append((char) c);
			}

			jsonResponse = (org.json.simple.JSONObject) new JSONParser().parse(responseString.toString());
		} catch (Exception ex) { }
		
		String encodedResourceUrl = URLEncoder.encode(resourceUrl, ISO_8859_1);
		String signatureCipher = httpMethod + "&" + encodedResourceUrl + "&"
				+ timestamp + "&" + nonce + "&" + clientId + "&"
				+ clientSecretKey;
		
		if (additionalParameters != null && !"".equals(additionalParameters))
			signatureCipher = signatureCipher + "&" + additionalParameters;

		MessageDigest messageDigest = MessageDigest
				.getInstance(signatureMethod);
		byte[] signatureBytes = messageDigest
				.digest(signatureCipher.getBytes());
		
		// encode signature as base 64 
		String signature = new String(Base64.encodeBase64(signatureBytes));
		
		String oAccessToken = AUTHORIZATION_REALM + jsonResponse.get("access_token").toString();

		oAuth.put(AUTHORIZATION, oAccessToken);
		oAuth.put(TIMESTAMP, String.valueOf(timestamp));
		oAuth.put(NONCE, nonce);
		oAuth.put(SIGNATURE_METHOD, signatureMethod);
		oAuth.put(SIGNATURE, signature);

		System.out.println(signatureCipher);
		
		return oAuth;
	}
}
