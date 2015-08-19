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

import com.interswitchng.techquest.payment.purchase.sample.codes.utils.InterswitchAuth;
import com.interswitchng.techquest.payment.purchase.sample.codes.utils.CustomOAuth;

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

	public static void purchaseRequest() throws NoSuchAlgorithmException,
			ClientProtocolException, IOException, JSONException {

		String customerId = "1407002510";
		
		String amount = "100.00";
		
		String authData = "dJ1rypdsZUa2T8U6DG7lwJL9gtzqky8jrRBB60yLDI/fGykojiA7sogz7OT3VsiYegX2oU7h/Njx8f0SJ6oCM7IIRrxCttH55mai+V0NxMJpr/5TnAHUkJLm1NL9w31K1wwS/1MPAnd4kLowqdoyauvrk9GTYB2K9PfBQQY/H17WYiicK4qcZRGriIJ1dhmYH9XcI7vbDEGt5Hx4RZajYH7huZfkJEI12Z5Vf4+63Bx57FVebFcgcDLF2R2frik67et60k+yby/SkIySx0JLiMrdd3HzuB+1J/cfLN/noJDT8nlYkrnC4Aul9KUWlfPY8dWeQK4nit7O4Av9N+s9fQ==";
		
		String currency = "NGN";
		
		String paymentReference = "23129";
		
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
		HashMap<String, String> customOAuth = CustomOAuth
				.generateCustomOAuth(httpMethod, resourceUrl2, clientId,
						clientSecretKey, additionalParameters, signatureMethod);

		// Write HTTP request to post
		HttpClient client = new DefaultHttpClient();
		HttpPost post = new HttpPost(resourceUrl);

		// Set headers for authorization
		post.setHeader("Authorization", customOAuth.get(AUTHORIZATION));
		post.setHeader("Timestamp", customOAuth.get(TIMESTAMP));
		post.setHeader("Nonce", customOAuth.get(NONCE));
		post.setHeader("Signature", customOAuth.get(SIGNATURE));
		post.setHeader("SignatureMethod", customOAuth.get(SIGNATURE_METHOD));

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
				+ customOAuth.get(AUTHORIZATION));
		System.out.println("Timestamp: " + customOAuth.get(TIMESTAMP));
		System.out.println("Nonce: " + customOAuth.get(NONCE));
		System.out.println("Signature: " + customOAuth.get(SIGNATURE));
		System.out.println("SignatureMethod: "
				+ customOAuth.get(SIGNATURE_METHOD));
	}

}
