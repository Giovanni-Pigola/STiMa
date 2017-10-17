package com.example.giovanni.tcc.Auxiliar;

import android.content.Context;
import android.content.Intent;
import android.util.Base64;
import android.util.Log;

import com.example.giovanni.tcc.EntradaActivity;
import com.example.giovanni.tcc.EntradaNegadaActivity;
import com.example.giovanni.tcc.HomeActivity;
import com.example.giovanni.tcc.InterfacePortaActivity;
import com.example.giovanni.tcc.LoginActivity;
import com.example.giovanni.tcc.R;
import com.example.giovanni.tcc.StartActivityNFC;
import com.example.giovanni.tcc.WelcomeActivity;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * Created by Giovanni on 18/09/2017.
 */

public class DoorAccess {

    private SecretKey secretKey = null;

    /**
     *
     * Test Door checks which response is given by the server and sets the correct activity for the redirect
     *
     * **/
    public Intent testDoor(Context context, String tagID, String token, String userID, Key publicKeyServer){

        //Log.i("tokenNFC lido", token);

        MediaType JSON = MediaType.parse("application/json; charset=utf-8");
        OkHttpClient client = new OkHttpClient();

        JSONObject jsonBodyParams = new JSONObject();

        /* puts read tagID in JSON */
        try {
            jsonBodyParams.put("tagID", tagID);
        } catch (JSONException e) {
            e.printStackTrace();
        }

        /* add UID to second JSON */
        JSONObject jsonBodyParamsRSA = new JSONObject();
        try {
            jsonBodyParamsRSA.put("userID", userID);
        } catch (JSONException e) {
            e.printStackTrace();
        }

        /* reads symmetric key from internal memory */
        byte[] SYMKEYb = null;
        try {
            FileInputStream SYMKEY = context.openFileInput("secretKey");
            SYMKEYb = new byte[SYMKEY.available()];
            SYMKEY.read(SYMKEYb);
            SYMKEY.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        /*cipher credential JSON with AES symmetric key*/
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
            //Log.i("sym key 64", cipherString);
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
        //Log.i("encoded RSA", Base64.encodeToString(encodedBytesRSA, Base64.DEFAULT));

        /* build new JSON with ciphered texts */
        JSONObject jsonBodyParamsEncrypted = new JSONObject();
        try {
            jsonBodyParamsEncrypted.put("data_encrypted", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
            jsonBodyParamsEncrypted.put("data_encrypted_2", Base64.encodeToString(encodedBytesRSA, Base64.DEFAULT));
        } catch (JSONException e) {
            e.printStackTrace();
        }

        /* makes request to server */
        RequestBody loginBody = RequestBody.create(JSON, jsonBodyParamsEncrypted.toString());
        Request request = new Request.Builder()
                .url(context.getResources().getString(R.string.door_access))
                .header("Content-Type", "application/json")
                .header("Authorization", "JWT " + token)
                .post(loginBody)
                .build();
        Log.i("request", String.valueOf(request.headers()));
        Log.i("request", String.valueOf(jsonBodyParams.toString()));
        Log.i("request", String.valueOf(request));
        Response response = null;

        try {
            response = client.newCall(request).execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Log.i("RESPONSE", String.valueOf(response));
        Log.i("RESPONSE", String.valueOf(response.isSuccessful()));

        Intent intentPorta;
        if (response.isSuccessful()) {

            String responseString = "";
            String facilityID = "Não identificado";
            JSONObject responseDoor = null;

            try {
                responseDoor = new JSONObject(response.body().string());
            } catch (IOException | JSONException e) {
                e.printStackTrace();
            }

            /* get encrypted JSON */
            String stringResponseEncrypted = "";
            try {
                stringResponseEncrypted = responseDoor.getString("data_encrypted");
                //Log.i("enc response login", stringResponseEncrypted);
            } catch (JSONException e) {
                e.printStackTrace();
            }

            /* decode and decipher server response to get token set */
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

            JSONObject responseBodyJsonDecrypted = null;
            try {
                responseBodyJsonDecrypted = new JSONObject(decipherString);
            } catch (JSONException e) {
                e.printStackTrace();
            }

            try {
                responseString = responseBodyJsonDecrypted.getString("Response");
            } catch (JSONException e) {
                e.printStackTrace();
            }

            /* checks which action to take based on the door authorization response*/
            switch (responseString){
                case "Open Access":
                    intentPorta = new Intent(context, EntradaActivity.class);
                    break;
                case "Restricted Access":
                    intentPorta = new Intent(context, InterfacePortaActivity.class);
                    break;
                case "No Access":
                    intentPorta = new Intent(context, EntradaNegadaActivity.class);
                    break;
                case "Facility Access":
                    intentPorta = new Intent(context, WelcomeActivity.class);
                    try {
                        facilityID = responseBodyJsonDecrypted.getString("FacilityID");
                        Log.i("facility ID DA", facilityID);
                    } catch (JSONException e) {
                        e.printStackTrace();
                    }
                    intentPorta.putExtra("facilityID", facilityID);
                    intentPorta.putExtra("entry", false);
                    break;
                default:
                    //Log.i("entrou default", "entrou default door switch");
                    intentPorta = new Intent(context, LoginActivity.class);
                    break;
            }

        } else {
            intentPorta = new Intent(context, EntradaNegadaActivity.class);
        }
        response.close();
    return intentPorta;
    }


}
