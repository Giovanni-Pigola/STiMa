package com.example.giovanni.tcc.Security;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import com.example.giovanni.tcc.Auxiliar.InternalFileReader;
import com.example.giovanni.tcc.R;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * Created by Giovanni on 04/08/2017.
 */

public class AccessToken {

    private SharedPreferences sharedPreferences;

    private OkHttpClient client = new OkHttpClient();
    private MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private JSONObject jsonBodyParams = new JSONObject();
    private JSONObject jsonBodyParamsRefresh = new JSONObject();

    private Boolean loggedIn = false;

    private String token;
    private String refreshToken;

    private String userID;

    private FileInputStream FJWT;
    private FileInputStream FID;
    private FileInputStream FJWR;
    private FileOutputStream FOST;

    private Key publicKey = null;
    private Key privateKey = null;
    private Key publicKeyServer = null;

    private SecretKey secretKey = null;

    /**
     *
     * Valida Login validates User Access Token with the validation server
     *
     * In the case that the Access Token is expired the function then sends the Refresh Token to the server for verification
     *
     * The response then is a new Access Token issued by the server that overwrites the previous Token in the internal memory
     *
     * The result is a boolean marking whether or not the validation process was successful
     *
     * **/
    public Boolean validaLogin(Context context) throws IOException {

        /* Reads Access Token, Refresh Token and UID from internal memory */
        FJWT = context.openFileInput("JWToken");
        InternalFileReader IFT = new InternalFileReader();
        token = IFT.readFile(FJWT);
        Log.i("tokenlidoT", token);

        FJWR = context.openFileInput("JWRefreshToken");
        InternalFileReader IFR = new InternalFileReader();
        refreshToken = IFR.readFile(FJWR);
        Log.i("tokenlidoR", refreshToken);

        FID = context.openFileInput("UID");
        InternalFileReader IFU = new InternalFileReader();
        userID = IFU.readFile(FID);
        //Log.i("UIDLido", userID);

        /* Reads server public key from internal memory and builds RSA key from it */
        try{
            FileInputStream keyPubS = context.openFileInput("publicKeyServer");
            byte[] encKey3 = new byte[keyPubS.available()];
            keyPubS.read(encKey3);
            keyPubS.close();

            //Log.i("len b Public Server", String.valueOf(encKey3.length));
            X509EncodedKeySpec pubServerEncoded = new X509EncodedKeySpec(encKey3);
            publicKeyServer = KeyFactory.getInstance("RSA").generatePublic(pubServerEncoded);
            //Log.i("server publicKey", Base64.encodeToString(publicKeyServer.getEncoded(), Base64.DEFAULT));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        /* creates HTTP client builder and sets connection timout to 30 seconds */
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.connectTimeout(30, TimeUnit.SECONDS);
        builder.readTimeout(30, TimeUnit.SECONDS);
        builder.writeTimeout(30, TimeUnit.SECONDS);
        client = builder.build();

        if (token!=null){
            /* Puts Access Token in first JSON */
            try {
                jsonBodyParams.put("token", token);
                //Log.i("tokenLidoInternal", token);
            } catch (JSONException e) {
                e.printStackTrace();
            }

            JSONObject jsonBodyParamsRSA = new JSONObject();
            JSONObject jsonBodyParamsEncrypted = new JSONObject();
            JSONObject jsonBodyParamsRefreshEncrypted = new JSONObject();

            /* Puts Access Token in second JSON */
            try {
                jsonBodyParamsRSA.put("userID", userID);
            } catch (JSONException e) {
                e.printStackTrace();
            }

            /* get symmetric key from memory*/
            byte[] SYMKEYb = null;
            try {
                FileInputStream SYMKEY = context.openFileInput("secretKey");
                SYMKEYb = new byte[SYMKEY.available()];
                SYMKEY.read(SYMKEYb);
                SYMKEY.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

            /* cipher first JSON with symmetric key */
            String cipherString = "";
            byte[] encodedBytes = null;
            try {
                secretKey = new SecretKeySpec(SYMKEYb, 0, SYMKEYb.length, "AES");
                //Log.i("key received length", String.valueOf(SYMKEYb.length));
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
                byte[] cipherIV = cipher.getIV();
                String cipherIVString = new String(cipherIV,"UTF-8");
                //Log.i("IV Length", String.valueOf(cipherIVString.length()));
                encodedBytes = cipher.doFinal((cipherIVString + jsonBodyParams.toString()).getBytes(Charset.forName("UTF-8")));
                cipherString = Base64.encodeToString(encodedBytes, Base64.DEFAULT);
                //Log.i("sym key 64", Base64.encodeToString(SYMKEYb, Base64.DEFAULT));
            } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
            /* cipher second JSON with server public key*/
            byte[] encodedBytesRSA = null;
            try {
                Cipher c = Cipher.getInstance("RSA/NONE/OAEPwithSHA-512andMGF1Padding");
                c.init(Cipher.ENCRYPT_MODE, publicKeyServer);
                encodedBytesRSA = c.doFinal(jsonBodyParamsRSA.toString().getBytes());
            } catch (Exception e) {
                Log.e("encrypted", "RSA encryption error");
            }

            /* build new JSON with ciphered texts */
            try {
                jsonBodyParamsEncrypted.put("data_encrypted", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
                jsonBodyParamsEncrypted.put("data_encrypted_2", Base64.encodeToString(encodedBytesRSA, Base64.DEFAULT));
            } catch (JSONException e) {
                e.printStackTrace();
            }

            /* make request to server */
            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParamsEncrypted.toString());
            Request request = new Request.Builder()
                    .url(context.getResources().getString(R.string.verify_url))
                    .header("Content-Type", "application/json")
                    .post(loginBody)
                    .build();
            Log.i("Request Header", String.valueOf(request.headers()));
            Log.i("Request data", String.valueOf(jsonBodyParams.toString()));
            Log.i("Encrypted token", cipherString);
            Log.i("Encrypted UID", Base64.encodeToString(encodedBytesRSA, Base64.DEFAULT));
            Log.i("Request info", String.valueOf(request));
            Response response = null;

            try {
                response = client.newCall(request).execute();
            } catch (IOException e) {
                //Log.i("INITIRESPONSE", "FAIL");
                e.printStackTrace();
            }
            Log.i("RESPONSE", String.valueOf(response));
            Log.i("RESPONSE", String.valueOf(response.isSuccessful()));

            if (!response.isSuccessful()) {

                if (refreshToken!=null){
                    /* Puts Refresh Token in first JSON */
                    try {
                        jsonBodyParamsRefresh.put("refresh", refreshToken);
                        //Log.i("refreshTokenLido", refreshToken);
                    } catch (JSONException e) {
                        e.printStackTrace();
                    }

                    /* cipher fist JSON with symmetric key*/
                    String cipherStringRefresh = "";
                    byte[] encodedBytesRefresh = null;
                    try {
                        //Log.i("key received length", String.valueOf(SYMKEYb.length));
                        Cipher cipherRefresh = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipherRefresh.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
                        byte[] cipherIV = cipherRefresh.getIV();
                        String cipherIVString = new String(cipherIV,"UTF-8");
                        //Log.i("IV Length", String.valueOf(cipherIVString.length()));
                        encodedBytesRefresh = cipherRefresh.doFinal((cipherIVString + jsonBodyParamsRefresh.toString()).getBytes(Charset.forName("UTF-8")));
                        cipherStringRefresh = Base64.encodeToString(encodedBytesRefresh, Base64.DEFAULT);
                        //Log.i("sym key 64", Base64.encodeToString(SYMKEYb, Base64.DEFAULT));
                    } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException e) {
                        e.printStackTrace();
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    } catch (NoSuchPaddingException e) {
                        e.printStackTrace();
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                    }

                    /* cipher second JSON with server public key */
                    byte[] encodedBytesRefreshRSA = null;
                    try {
                        Cipher cr = Cipher.getInstance("RSA/NONE/OAEPwithSHA-512andMGF1Padding");
                        cr.init(Cipher.ENCRYPT_MODE, publicKeyServer);
                        encodedBytesRefreshRSA = cr.doFinal(jsonBodyParamsRSA.toString().getBytes());
                    } catch (Exception e) {
                        Log.e("encrypted", "RSA encryption error");
                    }

                    /* build new JSON with ciphered texts */
                    try {
                        jsonBodyParamsRefreshEncrypted.put("data_encrypted", Base64.encodeToString(encodedBytesRefresh, Base64.DEFAULT));
                        jsonBodyParamsRefreshEncrypted.put("data_encrypted_2", Base64.encodeToString(encodedBytesRefreshRSA, Base64.DEFAULT));
                    } catch (JSONException e) {
                        e.printStackTrace();
                    }

                    /* make request to server */
                    RequestBody refreshBody = RequestBody.create(JSON, jsonBodyParamsRefreshEncrypted.toString());
                    Request requestRefresh = new Request.Builder()
                            .url(context.getResources().getString(R.string.verify_url_refresh_token))
                            .header("Content-Type", "application/json")
                            .post(refreshBody)
                            .build();
                    Log.i("Request Header", String.valueOf(requestRefresh.headers()));
                    Log.i("Request data", String.valueOf(jsonBodyParamsRefresh.toString()));
                    Log.i("Encrypted token", cipherStringRefresh);
                    Log.i("Encrypted UID", Base64.encodeToString(encodedBytesRefreshRSA, Base64.DEFAULT));
                    Log.i("Request info", String.valueOf(requestRefresh));
                    Response responseRefresh = null;

                    try {
                        responseRefresh = client.newCall(requestRefresh).execute();
                    } catch (IOException e) {
                        //Log.i("INITIRESPONSEREFRESH", "FAIL");
                        e.printStackTrace();
                    }
                    Log.i("RESPONSEREFRESH", String.valueOf(responseRefresh));
                    Log.i("RESPONSEREFRESH", String.valueOf(responseRefresh.isSuccessful()));

                    if (!responseRefresh.isSuccessful()){
                        loggedIn = false;
                        Log.i("RESULT", "response not successfull");
                        throw new IOException("Unexpected code " + responseRefresh);

                    }else {

                        Log.i("RESULTREFRESH", "refresh response successfull");
                        JSONObject responseBodyJson = null;
                        JSONObject responseBodyJsonDecrypted = null;

                        try {
                            responseBodyJson = new JSONObject(responseRefresh.body().string());
                        } catch (JSONException | IOException e) {
                            e.printStackTrace();
                        }


                        String stringResponseEncrypted = "";
                        String stringResponseSignature = "";
                        try {
                            stringResponseEncrypted = responseBodyJson.getString("data_encrypted");
                            stringResponseSignature = responseBodyJson.getString("signature");
                            Log.i("enc response signature", stringResponseSignature);
                        } catch (JSONException e) {
                            e.printStackTrace();
                        }

                        Signature signature = null;
                        try {
                            signature = Signature.getInstance("SHA512withECDSA");
                            byte[] respose64 = Base64.decode(stringResponseEncrypted, Base64.DEFAULT);
                            byte[] signature64 = Base64.decode(stringResponseSignature, Base64.DEFAULT);
                            signature.update(respose64);
                            boolean signatureVerified = signature.verify(signature64);
                            Log.i("signature", String.valueOf(signatureVerified));
                        } catch (NoSuchAlgorithmException | SignatureException e) {
                            e.printStackTrace();
                        }



                        /* decode and decipher server response to get new Access Token */
                        String decipherString = "";
                        byte[] decodedBytes = null;
                        try {
                            byte[] respose64 = Base64.decode(stringResponseEncrypted, Base64.DEFAULT);
                            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
                            byte[] respose16 = cipher.doFinal(respose64);
                            //Log.i("respose16", String.valueOf(respose16.length));
                            //Log.i("respose16", String.valueOf(respose16.length - 15));
                            decodedBytes = new byte[respose16.length - 16];
                            //Log.i("decodedBytes empty", String.valueOf(decodedBytes.length));
                            System.arraycopy(respose16, 16, decodedBytes, 0, decodedBytes.length);
                            decipherString = new String(decodedBytes,"UTF-8");
                            //Log.i("tokens json", decipherString);
                        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        }

                        try {
                            responseBodyJsonDecrypted = new JSONObject(decipherString);
                        } catch (JSONException e) {
                            e.printStackTrace();
                        }

                        /* writes new Access Token to internal memory */
                        try {
                            assert responseBodyJson != null;
                            FOST = context.openFileOutput("JWToken", Context.MODE_PRIVATE);
                            String stringToken = responseBodyJsonDecrypted.getString("accessToken");
                            Log.i("New Access Token", stringToken);
                            FOST.write(stringToken.getBytes());
                            FOST.close();
                        } catch (IOException e) {
                            Log.i("IOE", "refreshAccess");
                            e.printStackTrace();
                        } catch (JSONException e) {
                            e.printStackTrace();
                        }

                        loggedIn = true;
                    }
                    responseRefresh.close();

                }else {
                    Log.i("RESULT", "refresh token non-existent");
                    loggedIn = false;
                }



            } else {
                Log.i("RESULT", "response successfull");
                loggedIn = true;
            }
            response.close();

        } else {
            loggedIn = false;
            Log.i("RESULT", "token non-existent");
        }

        return loggedIn;
    }

    /**
     *
     * Valida Login Token Return validates User Access Token with the validation server
     *
     * In the case that the Access Token is expired the function then sends the Refresh Token to the server for verification
     *
     * The response then is a new Access Token issued by the server that overwrites the previous Token in the internal memory
     *
     * The result is a the Access Token currently available after the validation process ends
     *
     * **/
    public String validaLoginTokenReturn(Context context) throws IOException {

        /* Reads Access Token, Refresh Token and UID from internal memory */
        FJWT = context.openFileInput("JWToken");
        InternalFileReader IFT = new InternalFileReader();
        token = IFT.readFile(FJWT);
        Log.i("tokenlidoT", token);

        FJWR = context.openFileInput("JWRefreshToken");
        InternalFileReader IFR = new InternalFileReader();
        refreshToken = IFR.readFile(FJWR);
        Log.i("tokenlidoR", refreshToken);

        FID = context.openFileInput("UID");
        InternalFileReader IFU = new InternalFileReader();
        userID = IFU.readFile(FID);
        Log.i("UIDLido", userID);

        /* Reads server public key from internal memory and builds RSA key from it */
        try{
            FileInputStream keyPubS = context.openFileInput("publicKeyServer");
            byte[] encKey3 = new byte[keyPubS.available()];
            keyPubS.read(encKey3);
            keyPubS.close();

            //Log.i("len b Public Server", String.valueOf(encKey3.length));
            X509EncodedKeySpec pubServerEncoded = new X509EncodedKeySpec(encKey3);
            publicKeyServer = KeyFactory.getInstance("RSA").generatePublic(pubServerEncoded);
            //Log.i("server publicKey", Base64.encodeToString(publicKeyServer.getEncoded(), Base64.DEFAULT));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        /* creates HTTP client builder and sets connection timout to 30 seconds */
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.connectTimeout(30, TimeUnit.SECONDS);
        builder.readTimeout(30, TimeUnit.SECONDS);
        builder.writeTimeout(30, TimeUnit.SECONDS);
        client = builder.build();

        if (token!=null){
            /* Puts Access Token in first JSON */
            try {
                jsonBodyParams.put("token", token);
                Log.i("tokenLidoInternal", token);
            } catch (JSONException e) {
                e.printStackTrace();
            }

            JSONObject jsonBodyParamsRSA = new JSONObject();
            JSONObject jsonBodyParamsEncrypted = new JSONObject();
            JSONObject jsonBodyParamsRefreshEncrypted = new JSONObject();

            /* Puts Access Token in second JSON */
            try {
                jsonBodyParamsRSA.put("userID", userID);
            } catch (JSONException e) {
                e.printStackTrace();
            }

            /* get symmetric key from memory*/
            byte[] SYMKEYb = null;
            try {
                FileInputStream SYMKEY = context.openFileInput("secretKey");
                SYMKEYb = new byte[SYMKEY.available()];
                SYMKEY.read(SYMKEYb);
                SYMKEY.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

            /* cipher fist JSON with symmetric key*/
            String cipherString = "";
            byte[] encodedBytes = null;
            try {
                secretKey = new SecretKeySpec(SYMKEYb, 0, SYMKEYb.length, "AES");
                //Log.i("key received length", String.valueOf(SYMKEYb.length));
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
                byte[] cipherIV = cipher.getIV();
                String cipherIVString = new String(cipherIV,"UTF-8");
                //Log.i("IV Length", String.valueOf(cipherIVString.length()));
                encodedBytes = cipher.doFinal((cipherIVString + jsonBodyParams.toString()).getBytes(Charset.forName("UTF-8")));
                cipherString = Base64.encodeToString(encodedBytes, Base64.DEFAULT);
                //Log.i("sym key 64", Base64.encodeToString(SYMKEYb, Base64.DEFAULT));
            } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }

            /* cipher second JSON with server public key*/
            byte[] encodedBytesRSA = null;
            try {
                Cipher c = Cipher.getInstance("RSA/NONE/OAEPwithSHA-512andMGF1Padding");
                c.init(Cipher.ENCRYPT_MODE, publicKeyServer);
                encodedBytesRSA = c.doFinal(jsonBodyParamsRSA.toString().getBytes());
            } catch (Exception e) {
                Log.e("encrypted", "RSA encryption error");
            }

            /* build new JSON with ciphered texts */
            try {
                jsonBodyParamsEncrypted.put("data_encrypted", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
                jsonBodyParamsEncrypted.put("data_encrypted_2", Base64.encodeToString(encodedBytesRSA, Base64.DEFAULT));
            } catch (JSONException e) {
                e.printStackTrace();
            }

            /* make request to server */
            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParamsEncrypted.toString());
            Request request = new Request.Builder()
                    .url(context.getResources().getString(R.string.verify_url))
                    .header("Content-Type", "application/json")
                    .post(loginBody)
                    .build();
            Log.i("Request Header", String.valueOf(request.headers()));
            Log.i("Request data", String.valueOf(jsonBodyParams.toString()));
            Log.i("Encrypted token", cipherString);
            Log.i("Encrypted UID", Base64.encodeToString(encodedBytesRSA, Base64.DEFAULT));
            Log.i("Request info", String.valueOf(request));
            Response response = null;

            try {
                response = client.newCall(request).execute();
            } catch (IOException e) {
                //Log.i("INITIRESPONSE", "FAIL");
                e.printStackTrace();
            }
            Log.i("RESPONSE", String.valueOf(response));
            Log.i("RESPONSE", String.valueOf(response.isSuccessful()));

            if (!response.isSuccessful()) {

                if (refreshToken!=null){
                    /* Puts Refresh Token in first JSON */
                    try {
                        jsonBodyParamsRefresh.put("refresh", refreshToken);
                        Log.i("refreshTokenLido", refreshToken);
                    } catch (JSONException e) {
                        e.printStackTrace();
                    }

                    /* cipher fist JSON with symmetric key*/
                    String cipherStringRefresh = "";
                    byte[] encodedBytesRefresh = null;
                    try {
                        //Log.i("key received length", String.valueOf(SYMKEYb.length));
                        Cipher cipherRefresh = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipherRefresh.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
                        byte[] cipherIV = cipherRefresh.getIV();
                        String cipherIVString = new String(cipherIV,"UTF-8");
                        //Log.i("IV Length", String.valueOf(cipherIVString.length()));
                        encodedBytesRefresh = cipherRefresh.doFinal((cipherIVString + jsonBodyParamsRefresh.toString()).getBytes(Charset.forName("UTF-8")));
                        cipherStringRefresh = Base64.encodeToString(encodedBytesRefresh, Base64.DEFAULT);
                        //Log.i("sym key 64", Base64.encodeToString(SYMKEYb, Base64.DEFAULT));
                        //Log.i("sym key 64", cipherStringRefresh);
                    } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException e) {
                        e.printStackTrace();
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    } catch (NoSuchPaddingException e) {
                        e.printStackTrace();
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                    }
                    /* cipher second JSON with server public key */
                    byte[] encodedBytesRefreshRSA = null;
                    try {
                        Cipher cr = Cipher.getInstance("RSA/NONE/OAEPwithSHA-512andMGF1Padding");
                        cr.init(Cipher.ENCRYPT_MODE, publicKeyServer);
                        encodedBytesRefreshRSA = cr.doFinal(jsonBodyParamsRSA.toString().getBytes());
                    } catch (Exception e) {
                        Log.e("encrypted", "RSA encryption error");
                    }
                    //Log.i("encoded RSA", Base64.encodeToString(encodedBytesRefreshRSA, Base64.DEFAULT));

                    /* build new JSON with ciphered texts */
                    try {
                        jsonBodyParamsRefreshEncrypted.put("data_encrypted", Base64.encodeToString(encodedBytesRefresh, Base64.DEFAULT));
                        jsonBodyParamsRefreshEncrypted.put("data_encrypted_2", Base64.encodeToString(encodedBytesRefreshRSA, Base64.DEFAULT));
                    } catch (JSONException e) {
                        e.printStackTrace();
                    }

                    /* make request to server */
                    RequestBody refreshBody = RequestBody.create(JSON, jsonBodyParamsRefreshEncrypted.toString());
                    Request requestRefresh = new Request.Builder()
                            .url(context.getResources().getString(R.string.verify_url_refresh_token))
                            .header("Content-Type", "application/json")
                            .post(refreshBody)
                            .build();
                    Log.i("Request Header", String.valueOf(requestRefresh.headers()));
                    Log.i("Request data", String.valueOf(jsonBodyParamsRefresh.toString()));
                    Log.i("Encrypted token", cipherStringRefresh);
                    Log.i("Encrypted UID", Base64.encodeToString(encodedBytesRefreshRSA, Base64.DEFAULT));
                    Log.i("Request info", String.valueOf(requestRefresh));
                    Response responseRefresh = null;

                    try {
                        responseRefresh = client.newCall(requestRefresh).execute();
                    } catch (IOException e) {
                        //Log.i("INITIRESPONSEREFRESH", "FAIL");
                        e.printStackTrace();
                    }
                    Log.i("RESPONSEREFRESH", String.valueOf(responseRefresh));
                    Log.i("RESPONSEREFRESH", String.valueOf(responseRefresh.isSuccessful()));

                    if (!responseRefresh.isSuccessful()){

                        Log.i("RESULT", "response not successfull");
                        throw new IOException("Unexpected code " + responseRefresh);

                    }else {
                        Log.i("RESULTREFRESH", "refresh response successfull");
                        JSONObject responseBodyJson = null;
                        JSONObject responseBodyJsonDecrypted = null;

                        try {
                            responseBodyJson = new JSONObject(responseRefresh.body().string());
                        } catch (JSONException | IOException e) {
                            e.printStackTrace();
                        }


                        String stringResponseEncrypted = "";
                        try {
                            stringResponseEncrypted = responseBodyJson.getString("data_encrypted");
                            //Log.i("enc response login", stringResponseEncrypted);
                        } catch (JSONException e) {
                            e.printStackTrace();
                        }

                        /* decode and decipher server response to get new Access Token */
                        String decipherString = "";
                        byte[] decodedBytes = null;
                        try {
                            byte[] respose64 = Base64.decode(stringResponseEncrypted, Base64.DEFAULT);
                            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
                            byte[] respose16 = cipher.doFinal(respose64);
                            //Log.i("respose16", String.valueOf(respose16.length));
                            //Log.i("respose16", String.valueOf(respose16.length - 15));
                            decodedBytes = new byte[respose16.length - 16];
                            //Log.i("decodedBytes empty", String.valueOf(decodedBytes.length));
                            System.arraycopy(respose16, 16, decodedBytes, 0, decodedBytes.length);
                            decipherString = new String(decodedBytes,"UTF-8");
                            //Log.i("tokens json", decipherString);
                        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException e) {
                            e.printStackTrace();
                        } catch (NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        } catch (NoSuchPaddingException e) {
                            e.printStackTrace();
                        } catch (InvalidKeyException e) {
                            e.printStackTrace();
                        }

                        try {
                            responseBodyJsonDecrypted = new JSONObject(decipherString);
                        } catch (JSONException e) {
                            e.printStackTrace();
                        }

                         /* writes new Access Token to internal memory */
                        try {
                            assert responseBodyJson != null;
                            FOST = context.openFileOutput("JWToken", Context.MODE_PRIVATE);
                            String stringToken = responseBodyJsonDecrypted.getString("accessToken");
                            token = stringToken;
                            FOST.write(stringToken.getBytes());
                            FOST.close();
                        } catch (IOException e) {
                            Log.i("IOE", "refreshAccess");
                            e.printStackTrace();
                        } catch (JSONException e) {
                            e.printStackTrace();
                        }


                    }
                    responseRefresh.close();

                }else {
                    Log.i("RESULT", "refresh token non-existent");

                }



            } else {
                Log.i("RESULT", "response successfull");

            }
            response.close();

        } else {

            Log.i("RESULT", "token non-existent");
        }

        return token;
    }

}
