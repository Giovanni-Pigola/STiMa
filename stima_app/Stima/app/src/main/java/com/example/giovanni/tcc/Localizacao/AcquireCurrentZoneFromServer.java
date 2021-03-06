package com.example.giovanni.tcc.Localizacao;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import com.example.giovanni.tcc.Auxiliar.InternalFileReader;
import com.example.giovanni.tcc.HomeActivity;
import com.example.giovanni.tcc.R;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
import java.util.ArrayList;

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
 * Created by Gabriel on 01/08/2017.
 */

public class AcquireCurrentZoneFromServer {

    private String facility = "";
    private String currentZone = "";
    private Boolean isRequestOver = true;
    private ResultResponse resultResponse = new ResultResponse();
    private Activity activity;

    private HomeActivity home = new HomeActivity();

    private SecretKey secretKey = null;

    private Key publicKeySign = null;
    private Key privateKeySign = null;
    private Key publicKeyServerSign = null;

    private FileInputStream FID;
    private FileInputStream FJWT;
    private FileInputStream FJWR;

    private String tokenLido;
    private String refreshTokenLido;

    public Boolean getRequestOver() {
        return isRequestOver;
    }

    public void setFacilityID(String facilityID){
        if(!facilityID.equals("")){
            facility = facilityID;
        }
    }


    public void run(OkHttpClient client, ArrayList<AccessPoint> accessPoints, final Context mContext, final HomeActivity activity2) throws Exception {


        JSONObject requestBodyJSON = new JSONObject();
        JSONObject apJSON;
        JSONArray acquisitionsJSONArray = new JSONArray();
        for (AccessPoint ap : accessPoints) {
            apJSON = new JSONObject();
            apJSON.put("BSSID", ap.getBSSID());
            apJSON.put("RSSI", ap.getRSSI());
            acquisitionsJSONArray.put(apJSON);
        }

        try {
            InternalFileReader IFR = new InternalFileReader();
            FID = mContext.openFileInput("UID");

            FJWT = mContext.openFileInput("JWToken");
            tokenLido = IFR.readFile(FJWT);
            //Log.i("tokenlidoHome", tokenLido);
            FJWT.close();

            FJWR = mContext.openFileInput("JWRefreshToken");
            refreshTokenLido = IFR.readFile(FJWR);
            //Log.i("refreshTokenlidoHome", refreshTokenLido);
            FJWR.close();

        } catch (FileNotFoundException e) {
            Log.i("FILE", "FILE NOT FOUND HOME");
            e.printStackTrace();
        } catch (IOException e) {
            Log.i("IOE", "HOME");
            e.printStackTrace();
        }

        requestBodyJSON.put("access_points", acquisitionsJSONArray);
        MediaType JSON = MediaType.parse("application/json; charset=utf-8");

        JSONObject jsonBodyParamsEncrypted = new JSONObject();

         /*encode login AES*/
        byte[] SYMKEYb = null;
        try {
            FileInputStream SYMKEY = mContext.openFileInput("secretKey");
            SYMKEYb = new byte[SYMKEY.available()];
            SYMKEY.read(SYMKEYb);
            SYMKEY.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        /* reads symmetric key from internal memory for signature */
        try {
            FileInputStream keyPrivSign = mContext.openFileInput("privateKeySign");
            byte[] encKey2Sign = new byte[keyPrivSign.available()];
            keyPrivSign.read(encKey2Sign);
            keyPrivSign.close();

            Log.i("len b Private 2", String.valueOf(encKey2Sign.length));
            PKCS8EncodedKeySpec pkcsencodedSign = new PKCS8EncodedKeySpec(encKey2Sign);
            privateKeySign = KeyFactory.getInstance("EC").generatePrivate(pkcsencodedSign);

            FileInputStream keyPubSign = mContext.openFileInput("publicKeySign");
            byte[] encKey1Sign = new byte[keyPubSign.available()];
            keyPubSign.read(encKey1Sign);
            keyPubSign.close();

            Log.i("len b Public 2", String.valueOf(encKey1Sign.length));
            X509EncodedKeySpec xencodedSign = new X509EncodedKeySpec(encKey1Sign);
            publicKeySign = KeyFactory.getInstance("EC").generatePublic(xencodedSign);

            FileInputStream keyPubSSign = mContext.openFileInput("publicKeyServerSign");
            byte[] encKey3Sign = new byte[keyPubSSign.available()];
            keyPubSSign.read(encKey3Sign);
            keyPubSSign.close();

            Log.i("len b Public Server", String.valueOf(encKey3Sign.length));
            X509EncodedKeySpec pubServerEncodedSign = new X509EncodedKeySpec(encKey3Sign);
            publicKeyServerSign = KeyFactory.getInstance("EC").generatePublic(pubServerEncodedSign);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        String cipherString = "";
        byte[] encodedBytes = null;
        byte[] signed = null;
        try {
            secretKey = new SecretKeySpec(SYMKEYb, 0, SYMKEYb.length, "AES");
            //Log.i("key received length", String.valueOf(SYMKEYb.length));
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
            byte[] cipherIV = cipher.getIV();
            String cipherIVString = new String(cipherIV, "UTF-8");
            //Log.i("IV Length", String.valueOf(cipherIVString.length()));
            encodedBytes = cipher.doFinal((cipherIVString + requestBodyJSON.toString()).getBytes(Charset.forName("UTF-8")));
            cipherString = Base64.encodeToString(encodedBytes, Base64.DEFAULT);
            //Log.i("sym key 64", Base64.encodeToString(SYMKEYb, Base64.DEFAULT));

            Signature signature = Signature.getInstance("SHA512withECDSA");
            signature.initSign((PrivateKey) privateKeySign);
            signature.update(encodedBytes);
            signed = signature.sign();
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }

        try {
            jsonBodyParamsEncrypted.put("data", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
            jsonBodyParamsEncrypted.put("signature", Base64.encodeToString(signed, Base64.DEFAULT));
        } catch (JSONException e) {
            e.printStackTrace();
        }
        RequestBody requestBody = RequestBody.create(JSON, jsonBodyParamsEncrypted.toString());

        Request request = new Request.Builder()
                .url(mContext.getString(R.string.predict_zone_url))
                .header("Content-Type", "application/json")
                .header("Authorization", "JWT " + tokenLido)
                .post(requestBody)
                .build();
        Log.i("Request headers", String.valueOf(request.headers()));
        Log.i("Request data", String.valueOf(requestBodyJSON.toString()));
        Log.i("Encrypted acquisition", cipherString);
        Log.i("Request info", String.valueOf(request));

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                e.printStackTrace();

                //runOnUiThread(new Runnable() {
                //    @Override
                //    public void run() {
                //
                //                "AAAAASomething went wrong, try again later", Toast.LENGTH_SHORT);
                //        toast.show();
                //    }
                //});
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (!response.isSuccessful()) {
                    //runOnUiThread(new Runnable() {
                    //    @Override
                    //    public void run() {
                    //
                    //                "BBBBBSomething went wrong, try again later", Toast.LENGTH_SHORT);
                    //        toast.show();
                    //    }
                    //});
                    throw new IOException("Unexpected code " + response);
                }

                currentZone = response.body().string();
                //currentZone = currentZone.substring(2, currentZone.length() - 2);
                JSONObject jsonObject = null;
                try {
                    jsonObject = new JSONObject(currentZone);
                } catch (JSONException e) {
                    e.printStackTrace();
                }

                    /* get encrypted JSON */
                String stringResponseEncrypted = "";
                String stringResponseSignature = "";
                try {
                    stringResponseEncrypted = jsonObject.getString("data");
                    stringResponseSignature = jsonObject.getString("signature");
                    Log.i("enc response login", stringResponseEncrypted);
                } catch (JSONException e) {
                    e.printStackTrace();
                }

                    /* decode and decipher server response to get token set */
                String decipherString = "";
                byte[] decodedBytes = null;
                try {
                    byte[] respose64 = Base64.decode(stringResponseEncrypted, Base64.DEFAULT);
                    byte[] signature64 = Base64.decode(stringResponseSignature, Base64.DEFAULT);
                    Log.i("signature 64", stringResponseSignature);

                    Signature signature = Signature.getInstance("SHA512withECDSA");
                    signature.initVerify((PublicKey) publicKeyServerSign);
                    signature.update(respose64);
                    boolean signatureVerified = signature.verify(signature64);
                    Log.i("sigVer", String.valueOf(signatureVerified));

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
                        //Log.i("Position response", decipherString);
                    } else {
                        JSONObject jsonBodyNoZone = new JSONObject();
                        jsonBodyNoZone.put("ZonaName", "Invalid Location");

                    }
                } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | SignatureException | JSONException e) {
                    e.printStackTrace();
                }

                JSONObject responseBodyJsonDecrypted = null;
                try {
                    responseBodyJsonDecrypted = new JSONObject(decipherString);
                } catch (JSONException e) {
                    e.printStackTrace();
                }

                try {
                    resultResponse.setZonaName(responseBodyJsonDecrypted.getString("ZonaName"));
                    Log.i("Resposta Local", resultResponse.getZonaName());

                } catch (JSONException e) {
                    e.printStackTrace();
                }

                final String localizacao = resultResponse.getZonaName();

                activity2.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        activity2.setStringLocalizacao(localizacao);
                    }
                });

                response.close();
                isRequestOver = true;
            }
        });

    }
}
