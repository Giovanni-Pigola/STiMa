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
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

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
    private Key publicKeySign = null;
    private Key privateKeySign = null;
    private Key publicKeyServerSign = null;
    private String uniqueID;

    /**
     *
     * Test Door checks which response is given by the server and sets the correct activity for the redirect
     *
     * **/
    public Intent testDoor(Context context, String tagID, String token){

        /* reads UID from internal memory */
        try {
            FileInputStream FISU = context.openFileInput("UID");
            InternalFileReader IFR = new InternalFileReader();
            uniqueID = IFR.readFile(FISU);
            //Log.i("UID lido", uniqueID);
            FISU.close();

        } catch (IOException e) {
            uniqueID = "";
            e.printStackTrace();
        }

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

        /* reads symmetric key from internal memory for signature */
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
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        /*cipher credential JSON with AES symmetric key*/
        String cipherString = "";
        byte[] encodedBytes = null;
        byte[] signed = null;
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

            Signature signature = Signature.getInstance("SHA512withECDSA");
            signature.initSign((PrivateKey) privateKeySign);
            signature.update(encodedBytes);
            signed = signature.sign();
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | SignatureException e) {
            e.printStackTrace();
        }

        /* build new JSON with ciphered texts */
        JSONObject jsonBodyParamsEncrypted = new JSONObject();
        try {
            jsonBodyParamsEncrypted.put("data", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
            jsonBodyParamsEncrypted.put("userID", uniqueID);
            jsonBodyParamsEncrypted.put("signature", Base64.encodeToString(signed, Base64.DEFAULT));
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
            JSONObject responseDoor = null;

            try {
                responseDoor = new JSONObject(response.body().string());
            } catch (IOException | JSONException e) {
                e.printStackTrace();
            }

            /* get encrypted JSON */
            String stringResponseEncrypted = "";
            String stringResponseSignature = "";
            try {
                stringResponseEncrypted = responseDoor.getString("data");
                stringResponseSignature = responseDoor.getString("signature");
                //Log.i("enc response login", stringResponseEncrypted);
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
                    //Log.i("tokens json", decipherString);
                } else {
                    intentPorta = new Intent(context, LoginActivity.class);
                    return intentPorta;
                }
            } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | SignatureException e) {
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
