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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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

    private Key publicKeySign = null;
    private Key privateKeySign = null;
    private Key publicKeyServerSign = null;

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
            publicKeyServer = KeyFactory.getInstance("EC").generatePublic(pubServerEncoded);
            //Log.i("server publicKey", Base64.encodeToString(publicKeyServer.getEncoded(), Base64.DEFAULT));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        /* creates HTTP client builder and sets connection timout to 30 seconds */
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.connectTimeout(30, TimeUnit.SECONDS);
        builder.readTimeout(30, TimeUnit.SECONDS);
        builder.writeTimeout(30, TimeUnit.SECONDS);
        client = builder.build();

        if (token!=null){

            /* reads symmetric key from internal memory for signature */
            byte[] signed = null;
            try {
                FileInputStream keyPrivSign = context.openFileInput("privateKeySign");
                byte[] encKey2Sign = new byte[keyPrivSign.available()];
                keyPrivSign.read(encKey2Sign);
                keyPrivSign.close();

                Log.i("len b Private 2", String.valueOf(encKey2Sign.length));
                PKCS8EncodedKeySpec pkcsencodedSign = new PKCS8EncodedKeySpec(encKey2Sign);
                privateKeySign = KeyFactory.getInstance("EC").generatePrivate(pkcsencodedSign);

                FileInputStream keyPubSign = context.openFileInput("publicKeySign");
                byte[] encKey1Sign = new byte[keyPubSign.available()];
                keyPubSign.read(encKey1Sign);
                keyPubSign.close();

                Log.i("len b Public 2", String.valueOf(encKey1Sign.length));
                X509EncodedKeySpec xencodedSign = new X509EncodedKeySpec(encKey1Sign);
                publicKeySign = KeyFactory.getInstance("EC").generatePublic(xencodedSign);

                FileInputStream keyPubSSign = context.openFileInput("publicKeyServerSign");
                byte[] encKey3Sign = new byte[keyPubSSign.available()];
                keyPubSSign.read(encKey3Sign);
                keyPubSSign.close();

                Log.i("len b Public Server", String.valueOf(encKey3Sign.length));
                X509EncodedKeySpec pubServerEncodedSign = new X509EncodedKeySpec(encKey3Sign);
                publicKeyServerSign = KeyFactory.getInstance("EC").generatePublic(pubServerEncodedSign);

                Signature signature = Signature.getInstance("SHA512withECDSA");
                signature.initSign((PrivateKey) privateKeySign);
                signature.update(token.getBytes());
                signed = signature.sign();
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | SignatureException | InvalidKeyException e) {
                e.printStackTrace();
            }

            /* Puts Access Token in first JSON */
            try {
                jsonBodyParams.put("data", token);
                jsonBodyParams.put("userID", userID);
                jsonBodyParams.put("signature", Base64.encodeToString(signed, Base64.DEFAULT));
                //Log.i("tokenLidoInternal", token);
            } catch (JSONException e) {
                e.printStackTrace();
            }

            JSONObject jsonBodyParamsRSA = new JSONObject();
            JSONObject jsonBodyParamsRefreshEncrypted = new JSONObject();

            /* make request to server */
            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParams.toString());
            Request request = new Request.Builder()
                    .url(context.getResources().getString(R.string.verify_url))
                    .header("Content-Type", "application/json")
                    .post(loginBody)
                    .build();
            Log.i("Request Header", String.valueOf(request.headers()));
            Log.i("Request data", String.valueOf(jsonBodyParams.toString()));
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
                    String cipherStringRefresh = "";
                    byte[] encodedBytesRefresh = null;
                    byte[] signedRefresh = null;
                    try {
                        //Log.i("key received length", String.valueOf(SYMKEYb.length));
                        secretKey = new SecretKeySpec(SYMKEYb, 0, SYMKEYb.length, "AES");
                        Cipher cipherRefresh = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipherRefresh.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
                        byte[] cipherIV = cipherRefresh.getIV();
                        String cipherIVString = new String(cipherIV,"UTF-8");
                        //Log.i("IV Length", String.valueOf(cipherIVString.length()));
                        encodedBytesRefresh = cipherRefresh.doFinal((cipherIVString + jsonBodyParamsRefresh.toString()).getBytes(Charset.forName("UTF-8")));
                        cipherStringRefresh = Base64.encodeToString(encodedBytesRefresh, Base64.DEFAULT);
                        //Log.i("sym key 64", Base64.encodeToString(SYMKEYb, Base64.DEFAULT));

                        Signature signatureRefresh = Signature.getInstance("SHA512withECDSA");
                        signatureRefresh.initSign((PrivateKey) privateKeySign);
                        signatureRefresh.update(encodedBytesRefresh);
                        signedRefresh = signatureRefresh.sign();

                    } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | SignatureException e) {
                        e.printStackTrace();
                    }

                    /* build new JSON with ciphered texts */
                    try {
                        jsonBodyParamsRefreshEncrypted.put("data", Base64.encodeToString(encodedBytesRefresh, Base64.DEFAULT));
                        jsonBodyParamsRefreshEncrypted.put("userID", userID);
                        jsonBodyParamsRefreshEncrypted.put("signature", Base64.encodeToString(signedRefresh, Base64.DEFAULT));
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
                    Log.i("Request data", String.valueOf(jsonBodyParamsRefreshEncrypted.toString()));
                    Log.i("Encrypted token", cipherStringRefresh);
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
                            stringResponseEncrypted = responseBodyJson.getString("data");
                            stringResponseSignature = responseBodyJson.getString("signature");
                            Log.i("enc response signature", stringResponseSignature);
                        } catch (JSONException e) {
                            e.printStackTrace();
                        }

                        /* decode and decipher server response to get new Access Token */
                        String decipherString = "";
                        byte[] decodedBytes = null;
                        try {
                            byte[] respose64 = Base64.decode(stringResponseEncrypted, Base64.DEFAULT);
                            byte[] signature64 = Base64.decode(stringResponseSignature, Base64.DEFAULT);

                            Signature signature = Signature.getInstance("SHA512withECDSA");
                            signature.initVerify((PublicKey) publicKeyServerSign);
                            signature.update(respose64);
                            boolean signatureVerified = signature.verify(signature64);

                            if (signatureVerified){
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
                            } else {
                                return loggedIn = false;
                                /* notify user on error? */
                            }

                        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | SignatureException e) {
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
            publicKeyServer = KeyFactory.getInstance("EC").generatePublic(pubServerEncoded);
            //Log.i("server publicKey", Base64.encodeToString(publicKeyServer.getEncoded(), Base64.DEFAULT));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        /* creates HTTP client builder and sets connection timout to 30 seconds */
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.connectTimeout(30, TimeUnit.SECONDS);
        builder.readTimeout(30, TimeUnit.SECONDS);
        builder.writeTimeout(30, TimeUnit.SECONDS);
        client = builder.build();

        if (token!=null){
            /* reads symmetric key from internal memory for signature */
            byte[] signed = null;
            try {
                FileInputStream keyPrivSign = context.openFileInput("privateKeySign");
                byte[] encKey2Sign = new byte[keyPrivSign.available()];
                keyPrivSign.read(encKey2Sign);
                keyPrivSign.close();

                Log.i("len b Private 2", String.valueOf(encKey2Sign.length));
                PKCS8EncodedKeySpec pkcsencodedSign = new PKCS8EncodedKeySpec(encKey2Sign);
                privateKeySign = KeyFactory.getInstance("EC").generatePrivate(pkcsencodedSign);

                FileInputStream keyPubSign = context.openFileInput("publicKeySign");
                byte[] encKey1Sign = new byte[keyPubSign.available()];
                keyPubSign.read(encKey1Sign);
                keyPubSign.close();

                Log.i("len b Public 2", String.valueOf(encKey1Sign.length));
                X509EncodedKeySpec xencodedSign = new X509EncodedKeySpec(encKey1Sign);
                publicKeySign = KeyFactory.getInstance("EC").generatePublic(xencodedSign);

                FileInputStream keyPubSSign = context.openFileInput("publicKeyServerSign");
                byte[] encKey3Sign = new byte[keyPubSSign.available()];
                keyPubSSign.read(encKey3Sign);
                keyPubSSign.close();

                Log.i("len b Public Server", String.valueOf(encKey3Sign.length));
                X509EncodedKeySpec pubServerEncodedSign = new X509EncodedKeySpec(encKey3Sign);
                publicKeyServerSign = KeyFactory.getInstance("EC").generatePublic(pubServerEncodedSign);

                Signature signature = Signature.getInstance("SHA512withECDSA");
                signature.initSign((PrivateKey) privateKeySign);
                signature.update(token.getBytes());
                signed = signature.sign();
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | SignatureException | InvalidKeyException e) {
                e.printStackTrace();
            }

            /* Puts Access Token in first JSON */
            try {
                jsonBodyParams.put("data", token);
                jsonBodyParams.put("userID", userID);
                jsonBodyParams.put("signature", Base64.encodeToString(signed, Base64.DEFAULT));
            } catch (JSONException e) {
                e.printStackTrace();
            }

            JSONObject jsonBodyParamsRSA = new JSONObject();
            JSONObject jsonBodyParamsRefreshEncrypted = new JSONObject();


            /* make request to server */
            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParams.toString());
            Request request = new Request.Builder()
                    .url(context.getResources().getString(R.string.verify_url))
                    .header("Content-Type", "application/json")
                    .post(loginBody)
                    .build();
            Log.i("Request Header", String.valueOf(request.headers()));
            Log.i("Request data", String.valueOf(jsonBodyParams.toString()));
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
                    String cipherStringRefresh = "";
                    byte[] encodedBytesRefresh = null;
                    byte[] signedRefresh = null;
                    try {
                        //Log.i("key received length", String.valueOf(SYMKEYb.length));
                        secretKey = new SecretKeySpec(SYMKEYb, 0, SYMKEYb.length, "AES");
                        Cipher cipherRefresh = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipherRefresh.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
                        byte[] cipherIV = cipherRefresh.getIV();
                        String cipherIVString = new String(cipherIV,"UTF-8");
                        //Log.i("IV Length", String.valueOf(cipherIVString.length()));
                        encodedBytesRefresh = cipherRefresh.doFinal((cipherIVString + jsonBodyParamsRefresh.toString()).getBytes(Charset.forName("UTF-8")));
                        cipherStringRefresh = Base64.encodeToString(encodedBytesRefresh, Base64.DEFAULT);
                        //Log.i("sym key 64", Base64.encodeToString(SYMKEYb, Base64.DEFAULT));
                        //Log.i("sym key 64", cipherStringRefresh);

                        Signature signatureRefresh = Signature.getInstance("SHA512withECDSA");
                        signatureRefresh.initSign((PrivateKey) privateKeySign);
                        signatureRefresh.update(encodedBytesRefresh);
                        signedRefresh = signatureRefresh.sign();

                    } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | SignatureException e) {
                        e.printStackTrace();
                    }

                    /* build new JSON with ciphered texts */
                    try {
                        jsonBodyParamsRefreshEncrypted.put("data", Base64.encodeToString(encodedBytesRefresh, Base64.DEFAULT));
                        jsonBodyParamsRefreshEncrypted.put("userID", userID);
                        jsonBodyParamsRefreshEncrypted.put("signature", Base64.encodeToString(signedRefresh, Base64.DEFAULT));
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
                    Log.i("Request data", String.valueOf(jsonBodyParamsRefreshEncrypted.toString()));
                    Log.i("Encrypted token", cipherStringRefresh);
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
                        String stringResponseSignature = "";
                        try {
                            stringResponseEncrypted = responseBodyJson.getString("data");
                            stringResponseSignature = responseBodyJson.getString("signature");
                            //Log.i("enc response login", stringResponseEncrypted);
                        } catch (JSONException e) {
                            e.printStackTrace();
                        }

                        /* decode and decipher server response to get new Access Token */
                        String decipherString = "";
                        byte[] decodedBytes = null;
                        try {
                            byte[] respose64 = Base64.decode(stringResponseEncrypted, Base64.DEFAULT);
                            byte[] signature64 = Base64.decode(stringResponseSignature, Base64.DEFAULT);

                            Signature signature = Signature.getInstance("SHA512withECDSA");
                            signature.initVerify((PublicKey) publicKeyServerSign);
                            signature.update(respose64);
                            boolean signatureVerified = signature.verify(signature64);

                            if (signatureVerified) {
                                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
                                byte[] respose16 = cipher.doFinal(respose64);
                                //Log.i("respose16", String.valueOf(respose16.length));
                                //Log.i("respose16", String.valueOf(respose16.length - 15));
                                decodedBytes = new byte[respose16.length - 16];
                                //Log.i("decodedBytes empty", String.valueOf(decodedBytes.length));
                                System.arraycopy(respose16, 16, decodedBytes, 0, decodedBytes.length);
                                decipherString = new String(decodedBytes, "UTF-8");
                                //Log.i("tokens json", decipherString);
                            } else {
                                return token;
                            }
                        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | SignatureException e) {
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
