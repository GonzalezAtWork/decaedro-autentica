package net.decaedro.autentica;

import com.google.gson.Gson;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;

import java.util.ArrayList;
import java.util.List;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;


import java.io.IOException;
import java.io.Serializable;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ParseAuthenticate implements ServerAuthenticate{

	public String MD5(String password) {
		String retorno = "";
		try {
			MessageDigest digest = java.security.MessageDigest.getInstance("MD5");
			digest.update(password.getBytes());
			byte messageDigest[] = digest.digest();
	  
			StringBuffer MD5Hash = new StringBuffer();
			for (int i = 0; i < messageDigest.length; i++) {
				String h = Integer.toHexString(0xFF & messageDigest[i]);
				while (h.length() < 2)
					h = "0" + h;
				MD5Hash.append(h);
			}
			retorno = MD5Hash.toString();	 
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return retorno;
	}

    @Override
    public String userSignUp(String name, String email, String pass, String authType) throws Exception {
        String authtoken = null;
        return authtoken;
    }

    @Override
    public User userSignIn(String device, String user, String pass, String authType) throws Exception {

		DefaultHttpClient httpClient = new DefaultHttpClient();
		String url = "http://zelaznog.net/Kalitera/ajax/autentica.php";
		pass = MD5(pass);	
        HttpPost httpPost = new HttpPost(url);
		List nameValuePairs = new ArrayList();
		nameValuePairs.add(new BasicNameValuePair("cpf", user));
		nameValuePairs.add(new BasicNameValuePair("senha", pass));
		nameValuePairs.add(new BasicNameValuePair("device", device));
	   
		httpPost.setEntity(new UrlEncodedFormEntity(nameValuePairs));

		User loggedUser = null;
        try {
            HttpResponse response = httpClient.execute(httpPost);
            String responseString = EntityUtils.toString(response.getEntity());

            if (response.getStatusLine().getStatusCode() != 200) {
                ParseComError error = new Gson().fromJson(responseString, ParseComError.class);
                throw new Exception("Error signing-in ["+error.code+"] - " + error.error);
            }

            loggedUser = new Gson().fromJson(responseString, User.class);

        } catch (IOException e) {
            e.printStackTrace();
        }

        return loggedUser;
    }

    private class ParseComError implements Serializable {
        int code;
        String error;
    }
}
