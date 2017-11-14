package com.example.giovanni.tcc;

import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.AsyncTask;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import com.example.giovanni.tcc.Auxiliar.InternalFileReader;
import com.example.giovanni.tcc.Security.AccessToken;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class StartActivity extends AppCompatActivity {

    private AccessToken accessToken;

    private FileOutputStream FOID;
    private FileOutputStream FOJWT;
    private FileOutputStream FOJWR;
    private FileOutputStream FOPVTK;
    private FileOutputStream FOPBCK;
    private FileOutputStream FOPBCKS;

    private FileInputStream FID;
    private FileInputStream FJWT;
    private FileInputStream FJWR;
    private FileInputStream FIPVTK;
    private FileInputStream FIPBCK;

    private Key publicKey = null;
    private Key privateKey = null;
    private Key publicKeyServer = null;

    private Boolean keyExists;
    private Boolean UIDExists = false;

    private String UIDstring;

    private byte[] UIDb;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        //setContentView(R.layout.activity_start);

        /* try to open UID from internal memory */
        try {
            FileInputStream FISU = openFileInput("UID");
//            UIDb = new byte[FISU.available()];
//            FISU.read(UIDb);
            InternalFileReader IFR = new InternalFileReader();
            UIDstring = IFR.readFile(FISU);
            UIDb = UIDstring.getBytes();
            FISU.close();
            UIDExists = true;
            Log.i("UID lido", UIDstring);

        } catch (IOException e) {
            UIDExists = false;
            e.printStackTrace();
        }
        /*creates random UID if there is not one already in memory and stores it*/
        //Log.i("UIDEXISTS", String.valueOf(UIDExists));
        if (!UIDExists){
            try {
                String uniqueID = UUID.randomUUID().toString();
                FileOutputStream FOSU = openFileOutput("UID", Context.MODE_PRIVATE);
                FOSU.write(uniqueID.getBytes());
                FOSU.close();
                UIDb = uniqueID.getBytes();
                Log.i("UID gerado", uniqueID);
            } catch (FileNotFoundException e) {
                Log.i("FILE", "FILE NOT FOUND LOGIN");
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        /* attempts to read mobile keypair and server public key for verification of existence */
        try {
            FileInputStream keyPub = openFileInput("publicKey");
            byte[] encKey1 = new byte[keyPub.available()];
            keyPub.read(encKey1);
            keyPub.close();

            Log.i("len b Public 2", String.valueOf(encKey1.length));
            X509EncodedKeySpec xencoded = new X509EncodedKeySpec(encKey1);
            publicKey = KeyFactory.getInstance("RSA").generatePublic(xencoded);
            Log.i("publicKey", Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT));

            FileInputStream keyPriv = openFileInput("privateKey");
            byte[] encKey2 = new byte[keyPriv.available()];
            keyPriv.read(encKey2);
            keyPriv.close();

            Log.i("len b Private 2", String.valueOf(encKey2.length));
            PKCS8EncodedKeySpec pkcsencoded = new PKCS8EncodedKeySpec(encKey2);
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(pkcsencoded);
            Log.i("privateKey", Base64.encodeToString(privateKey.getEncoded(), Base64.DEFAULT));

            FileInputStream keyPubS = openFileInput("publicKeyServer");
            byte[] encKey3 = new byte[keyPubS.available()];
            keyPubS.read(encKey3);
            keyPubS.close();

            Log.i("len b Public Server", String.valueOf(encKey3.length));
            X509EncodedKeySpec pubServerEncoded = new X509EncodedKeySpec(encKey3);
            publicKeyServer = KeyFactory.getInstance("RSA").generatePublic(pubServerEncoded);
            Log.i("server publicKey", Base64.encodeToString(publicKeyServer.getEncoded(), Base64.DEFAULT));

            keyExists = true;

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            Log.i("Keypair", "Keypair not found");
            keyExists = false;
            e.printStackTrace();
        }

        /* creates keypair and generate server public key in case any of the mentioned keys doesn't exist */
        if (!keyExists){
            try {
                byte[] serverPublicKey = Base64.decode("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", Base64.DEFAULT);

                KeyPairGenerator kpg = null;
                kpg = KeyPairGenerator.getInstance("RSA");

                /*generate keypair based on UUID*/
                SecureRandom random = new SecureRandom(UIDb);

                kpg.initialize(15360, random);
                KeyPair kp = kpg.genKeyPair();
                publicKey = kp.getPublic();
                Log.i("publicKey", Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT));
                privateKey = kp.getPrivate();
                Log.i("privateKey", Base64.encodeToString(privateKey.getEncoded(), Base64.DEFAULT));

                FOPBCK = openFileOutput("publicKey", Context.MODE_PRIVATE);
                Log.i("format Public", publicKey.getFormat());
                Log.i("len b Public", String.valueOf(publicKey.getEncoded().length));
                FOPBCK.write(publicKey.getEncoded());
                FOPBCK.close();

                FOPVTK = openFileOutput("privateKey", Context.MODE_PRIVATE);
                Log.i("format Private", privateKey.getFormat());
                Log.i("len b Private", String.valueOf(privateKey.getEncoded().length));
                FOPVTK.write(privateKey.getEncoded());
                FOPVTK.close();

                FOPBCKS = openFileOutput("publicKeyServer", Context.MODE_PRIVATE);
                X509EncodedKeySpec pubServerEncoded = new X509EncodedKeySpec(serverPublicKey);
                publicKeyServer = KeyFactory.getInstance("RSA").generatePublic(pubServerEncoded);
                //Log.i("format Public", publicKey.getFormat());
                //Log.i("len b Public", String.valueOf(publicKey.getEncoded().length));
                FOPBCKS.write(publicKeyServer.getEncoded());
                FOPBCKS.close();

            } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
                e.printStackTrace();
            }
        }


        accessToken = new AccessToken();

        new StartActivity.doHandShake().execute(publicKey, publicKeyServer, privateKey);

//        new StartActivity.tryInstaLogin().execute();

    }


    /**
     *
     * Instant Login checks if the User has already logged in previously and still has the tokens needed
     *
     * First it validates the User token set using the accessToken class
     *
     * Then on the result of that validation it redirects the User to either the Login activity or the Home activity
     *
     * **/
    private class tryInstaLogin extends AsyncTask<Object, Object, Void> {

        @Override
        protected void onPreExecute() {
            /*loadingDialog = ProgressDialog.show(HomeActivity.this,
                    "Please wait...", "Getting data from server");
            loadingDialog.setCancelable(false);*/
        }

        protected Void doInBackground(Object... params) {

            Intent nextActivity;

            /* checks token set and creates memory allocation for Access Token and Refresh Token if there isn't already space */
            Boolean bool = null;
            try {
                bool = accessToken.validaLogin(StartActivity.this);
            } catch (FileNotFoundException e) {
                Log.i("FILE", "NOT FOUND START");
                bool = false;
                try {
                    FOJWT = openFileOutput("JWToken", Context.MODE_PRIVATE);
                    FOJWT.write(0);
                    FOJWT.close();
                    FOJWR = openFileOutput("JWRefreshToken", Context.MODE_PRIVATE);
                    FOJWR.write(0);
                    FOJWR.close();
                } catch (IOException e1) {
                    Log.i("IOE", "START2");
                    e1.printStackTrace();
                }
            } catch (IOException e) {
                Log.i("IOE", "START");
                bool = false;
                e.printStackTrace();
            }

            /* checks result of the previous validation and redirects User to login if tokens don't come through, or to home if they pass */
            //Log.i("loga?", String.valueOf(bool));
            if (bool) {
                Log.i("LogIn", "loga direto");
                nextActivity = new Intent(StartActivity.this, HomeActivity.class);

            } else {
                Log.i("LogIn", "nao loga direto");
                nextActivity = new Intent(StartActivity.this, LoginActivity.class);
            }

            startActivity(nextActivity);
            finish();


            return null;
        }

        protected void onPostExecute() {

            //loadingDialog.dismiss();

        }
    }

    /**
     *
     * Handshake sends User public key and User UID to server encrypted with secure symmetric key
     * The symmetric key is sent to the server encrypted with the server's public key
     *
     * The server responds with a new symmetric key encripted with the received user public key
     * This second symmetric key will then be used for the rest of the message exchange in the app
     *
     * At the end of the process the function calls for the instant login function
     *
     *  **/
    private class doHandShake extends AsyncTask<Key, Void, Response> {

        @Override
        protected void onPreExecute() {
//            loadingDialog = ProgressDialog.show(HomeActivity.this,
//                    "Please wait...", "Getting data from server");
//            loadingDialog.setCancelable(false);
        }

        protected Response doInBackground(Key... params) {

            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            OkHttpClient client = new OkHttpClient();

            JSONObject jsonBodyParams = new JSONObject();
            JSONObject jsonBodyParamsEncrypted = new JSONObject();

            /* reado UID from internal memory */
            try {
                FileInputStream FISU = openFileInput("UID");
                InternalFileReader IFR = new InternalFileReader();
                UIDstring = IFR.readFile(FISU);
                FISU.close();
                //Log.i("UID lido", UIDstring);
            } catch (IOException e) {
                e.printStackTrace();
            }

            /* insert UID and Base64 encoded User public key in JSON */
            try {
                jsonBodyParams.put("userID", UIDstring);
                jsonBodyParams.put("publicKey", Base64.encodeToString(params[0].getEncoded(), Base64.DEFAULT));
            } catch (JSONException e) {
                e.printStackTrace();
            }

            /* creates symmetric key generator with 256 bit key defined */
            SecretKey handshakeSecretKey = null;
            try {
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(256); // AES is currently available in three key sizes: 128, 192 and 256 bits.The design and strength of all key lengths of the AES algorithm are sufficient to protect classified information up to the SECRET level
                handshakeSecretKey = keyGenerator.generateKey();

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            /* creates key and ciphers JSON using it */
            String cipherHandshakeString = "";
            byte[] encryptedHandshake = null;
            try {
                byte[] raw = handshakeSecretKey.getEncoded();
                SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                //Log.i("keysizehandshake", String.valueOf(skeySpec.getEncoded().length));
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(new byte[16]));
                byte[] cipherIV = cipher.getIV();
                String cipherIVString = new String(cipherIV,"UTF-8");
                //Log.i("IV Length", String.valueOf(cipherIVString.length()));
                encryptedHandshake = cipher.doFinal((cipherIVString + jsonBodyParams.toString()).getBytes(Charset.forName("UTF-8")));
                cipherHandshakeString = Base64.encodeToString(encryptedHandshake, Base64.DEFAULT);
                Log.i("sym key 64", Base64.encodeToString(raw, Base64.DEFAULT));

            } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }

            /* ciphers previous key usig server public key */
            byte[] encodedBytes = null;
            try {
                Cipher c = Cipher.getInstance("RSA/NONE/OAEPwithSHA-512andMGF1Padding");
                c.init(Cipher.ENCRYPT_MODE, publicKeyServer);
                encodedBytes = c.doFinal(handshakeSecretKey.getEncoded());
            } catch (Exception e) {
                Log.e("encrypted", "RSA encryption error");
                e.printStackTrace();
            }

            /* insert both ciphered texts in new JSON */
            try {
                jsonBodyParamsEncrypted.put("data_encrypted", cipherHandshakeString);
                jsonBodyParamsEncrypted.put("data_encrypted_2", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
            } catch (JSONException e) {
                e.printStackTrace();
            }

            /* send new JSON to server */
            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParamsEncrypted.toString());
            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.handshake))
                    .header("Content-Type", "application/json")
                    .post(loginBody)
                    .build();
            Log.i("Request header", String.valueOf(request.headers()));
            Log.i("Request data", String.valueOf(jsonBodyParams.toString()));
            Log.i("Encrypted data", cipherHandshakeString);
            Log.i("Encrypted key", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
            Log.i("Request info", String.valueOf(request));
            Response response = null;

            try {
                response = client.newCall(request).execute();
            } catch (IOException e) {
                e.printStackTrace();
            }


            return response;

        }

        protected void onPostExecute(Response response) {

//            loadingDialog.dismiss();

            if (response.isSuccessful()) {
                JSONObject responseBodyJson = null;
                String responseString = null;

                String encryptedDataR = "";
                try {
                    responseBodyJson = new JSONObject(response.body().string());
                    encryptedDataR = responseBodyJson.getString("data_encrypted");
                    Log.i("Encrypted response key", encryptedDataR);
                } catch (IOException | JSONException e) {
                    e.printStackTrace();
                }

                /* decodes and decipher server response to get session symmetric key */
                byte[] decodedBytesR = null;
                String decryptedDataR = "";
                SecretKey secretKey = null;
                try {
                    byte[] SYMKEY64 = Base64.decode(encryptedDataR, Base64.DEFAULT);
                    Cipher d = Cipher.getInstance("RSA/NONE/OAEPwithSHA-512andMGF1Padding");
                    d.init(Cipher.DECRYPT_MODE, privateKey);
                    decodedBytesR = d.doFinal(SYMKEY64);
                    byte[] SYMKEY = Base64.decode(decodedBytesR, Base64.DEFAULT);
                    //Log.i("decoded key lenght", String.valueOf(SYMKEY.length));
                    secretKey = new SecretKeySpec(SYMKEY, 0, SYMKEY.length, "AES");
                    //decryptedDataR = new String(,"UTF-8");
                    //Log.i("decoded key", decryptedDataR);
                    Log.i("sym key 64", Base64.encodeToString(secretKey.getEncoded(), Base64.DEFAULT));
                } catch (Exception e) {
                    Log.e("decoded", "RSA decryption error");
                    e.printStackTrace();
                }

                /* writes session symmetric key to internal memory */
                try {
                    FileOutputStream FOSSYM = openFileOutput("secretKey", Context.MODE_PRIVATE);
                    FOSSYM.write(secretKey.getEncoded());
                    FOSSYM.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            } else {

                Toast toast = Toast.makeText(StartActivity.this,
                        "Something went wrong, try again later", Toast.LENGTH_SHORT);
                toast.show();
                Log.i("response handshake", response.toString());
                Log.i("response handshake", response.body().toString());

            }
            new StartActivity.tryInstaLogin().execute();

        }
    }

}
