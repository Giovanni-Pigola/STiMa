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
import javax.crypto.KeyAgreement;
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

    private FileInputStream FID;
    private FileInputStream FJWT;
    private FileInputStream FJWR;
    private FileInputStream FIPVTK;
    private FileInputStream FIPBCK;

    private Key publicKey = null;
    private Key privateKey = null;
    private Key publicKeyServer = null;

    private Key publicKeySign = null;
    private Key privateKeySign = null;
    private Key publicKeyServerSign = null;

    private Boolean keyExists;
    private Boolean UIDExists = false;

    private String UIDstring;

    private byte[] UIDb;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_start);



    }

    @Override
    protected void onStart() {
        super.onStart();

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
            publicKey = KeyFactory.getInstance("EC").generatePublic(xencoded);
            Log.i("publicKey", Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT));

            FileInputStream keyPriv = openFileInput("privateKey");
            byte[] encKey2 = new byte[keyPriv.available()];
            keyPriv.read(encKey2);
            keyPriv.close();

            Log.i("len b Private 2", String.valueOf(encKey2.length));
            PKCS8EncodedKeySpec pkcsencoded = new PKCS8EncodedKeySpec(encKey2);
            privateKey = KeyFactory.getInstance("EC").generatePrivate(pkcsencoded);
            Log.i("privateKey", Base64.encodeToString(privateKey.getEncoded(), Base64.DEFAULT));

            FileInputStream keyPubS = openFileInput("publicKeyServer");
            byte[] encKey3 = new byte[keyPubS.available()];
            keyPubS.read(encKey3);
            keyPubS.close();

            Log.i("len b Public Server", String.valueOf(encKey3.length));
            X509EncodedKeySpec pubServerEncoded = new X509EncodedKeySpec(encKey3);
            publicKeyServer = KeyFactory.getInstance("EC").generatePublic(pubServerEncoded);
            Log.i("server publicKey", Base64.encodeToString(publicKeyServer.getEncoded(), Base64.DEFAULT));

            //////////////////////////////////////////////////////////////////


            FileInputStream keyPubSign = openFileInput("publicKeySign");
            byte[] encKey1Sign = new byte[keyPubSign.available()];
            keyPubSign.read(encKey1Sign);
            keyPubSign.close();

            Log.i("len b Public 2", String.valueOf(encKey1Sign.length));
            X509EncodedKeySpec xencodedSign = new X509EncodedKeySpec(encKey1Sign);
            publicKeySign = KeyFactory.getInstance("EC").generatePublic(xencodedSign);
            Log.i("publicKey", Base64.encodeToString(publicKeySign.getEncoded(), Base64.DEFAULT));

            FileInputStream keyPrivSign = openFileInput("privateKeySign");
            byte[] encKey2Sign = new byte[keyPrivSign.available()];
            keyPrivSign.read(encKey2Sign);
            keyPrivSign.close();

            Log.i("len b Private 2", String.valueOf(encKey2Sign.length));
            PKCS8EncodedKeySpec pkcsencodedSign = new PKCS8EncodedKeySpec(encKey2Sign);
            privateKeySign = KeyFactory.getInstance("EC").generatePrivate(pkcsencodedSign);
            Log.i("privateKey", Base64.encodeToString(privateKeySign.getEncoded(), Base64.DEFAULT));

            FileInputStream keyPubSSign = openFileInput("publicKeyServerSign");
            byte[] encKey3Sign = new byte[keyPubSSign.available()];
            keyPubSSign.read(encKey3Sign);
            keyPubSSign.close();

            Log.i("len b Public Server", String.valueOf(encKey3Sign.length));
            X509EncodedKeySpec pubServerEncodedSign = new X509EncodedKeySpec(encKey3Sign);
            publicKeyServerSign = KeyFactory.getInstance("EC").generatePublic(pubServerEncodedSign);
            Log.i("server publicKey", Base64.encodeToString(publicKeyServerSign.getEncoded(), Base64.DEFAULT));

            keyExists = true;

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            Log.i("Keypair", "Keypair not found");
            keyExists = false;
            e.printStackTrace();
        }

        /* creates keypair and generate server public key in case any of the mentioned keys doesn't exist */
        if (!keyExists){
            try {
                byte[] serverPublicKey = Base64.decode("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBLq2LFjgKbIoSdo8+jG7vBiIAGPFYFWy7tgkB4f6ZtamycZoz7VLd4tP7zkORGvW3MC/awChWREUshSb+0+q31PkBAKxM7TCLPVKDNbF5pXpVHa+yMfbeXhp3vR+XLSyRWUL5VDG7nqSSvAkDZphFi1Nd4kShqdh7hp8ZdH4Kp27miGk=", Base64.DEFAULT);
                byte[] serverPublicKeySign = Base64.decode("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAotgA8yaFWZ5WGpUOzBaDDmWPrwEDLx2OT0E+F0rSROE5+Qn+grStvdI5K1EXx4Et7z4+VIt1QEV1EsF8MPsxmAoASDLlWYHbKtCodJzi6SGVKdgZuzrTVPq9cXF/WilHq4ELnmC4Q52hO+ivHJPls5/cehpnbQ50fwWBfAXAEl620xs=", Base64.DEFAULT);

                KeyPairGenerator kpg = null;
                kpg = KeyPairGenerator.getInstance("EC");

                /*generate keypair based on UUID*/
                SecureRandom random = new SecureRandom(UIDb);

                kpg.initialize(521, random);
                KeyPair kp = kpg.genKeyPair();
                publicKey = kp.getPublic();
                Log.i("publicKey", Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT));
                privateKey = kp.getPrivate();
                Log.i("privateKey", Base64.encodeToString(privateKey.getEncoded(), Base64.DEFAULT));

                FileOutputStream FOPBCK = openFileOutput("publicKey", Context.MODE_PRIVATE);
                Log.i("format Public", publicKey.getFormat());
                Log.i("len b Public", String.valueOf(publicKey.getEncoded().length));
                FOPBCK.write(publicKey.getEncoded());
                FOPBCK.close();

                FileOutputStream FOPVTK = openFileOutput("privateKey", Context.MODE_PRIVATE);
                Log.i("format Private", privateKey.getFormat());
                Log.i("len b Private", String.valueOf(privateKey.getEncoded().length));
                FOPVTK.write(privateKey.getEncoded());
                FOPVTK.close();

                FileOutputStream FOPBCKS = openFileOutput("publicKeyServer", Context.MODE_PRIVATE);
                X509EncodedKeySpec pubServerEncoded = new X509EncodedKeySpec(serverPublicKey);
                publicKeyServer = KeyFactory.getInstance("EC").generatePublic(pubServerEncoded);
                //Log.i("format Public", publicKey.getFormat());
                //Log.i("len b Public", String.valueOf(publicKey.getEncoded().length));
                FOPBCKS.write(publicKeyServer.getEncoded());
                FOPBCKS.close();

                /////////////////////////////////////////////////////////////////////

                KeyPairGenerator kpgSign = null;
                kpgSign = KeyPairGenerator.getInstance("EC");

                /*generate keypair based on UUID*/
                SecureRandom randomSign = new SecureRandom(UIDb);

                kpgSign.initialize(521, randomSign);
                KeyPair kpSign = kpgSign.genKeyPair();
                publicKeySign = kpSign.getPublic();
                Log.i("publicKeySign", Base64.encodeToString(publicKeySign.getEncoded(), Base64.DEFAULT));
                privateKeySign = kpSign.getPrivate();
                Log.i("privateKeySign", Base64.encodeToString(privateKeySign.getEncoded(), Base64.DEFAULT));

                FileOutputStream FOPBCKSign = openFileOutput("publicKeySign", Context.MODE_PRIVATE);
                Log.i("format Public Sign", publicKeySign.getFormat());
                Log.i("len b Public Sign", String.valueOf(publicKeySign.getEncoded().length));
                FOPBCKSign.write(publicKeySign.getEncoded());
                FOPBCKSign.close();

                FileOutputStream FOPVTKSign = openFileOutput("privateKeySign", Context.MODE_PRIVATE);
                Log.i("format Private Sign", privateKeySign.getFormat());
                Log.i("len b Private Sign", String.valueOf(privateKeySign.getEncoded().length));
                FOPVTKSign.write(privateKeySign.getEncoded());
                FOPVTKSign.close();

                FileOutputStream FOPBCKSSign = openFileOutput("publicKeyServerSign", Context.MODE_PRIVATE);
                X509EncodedKeySpec pubServerEncodedSign = new X509EncodedKeySpec(serverPublicKeySign);
                publicKeyServerSign = KeyFactory.getInstance("EC").generatePublic(pubServerEncodedSign);
                //Log.i("format Public Sign", publicKeySign.getFormat());
                //Log.i("len b Public Sign", String.valueOf(publicKeySign.getEncoded().length));
                FOPBCKSSign.write(publicKeyServerSign.getEncoded());
                FOPBCKSSign.close();

                ///////////////////////////////////////////////////////////////////

                KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
                keyAgreement.init(privateKey);
                keyAgreement.doPhase(publicKeyServer, true);

                byte[] secretKey = keyAgreement.generateSecret();

                byte[] decodedKeyBytes = new byte[32];
                //Log.i("decodedBytes empty", String.valueOf(decodedBytes.length));
                System.arraycopy(secretKey, 0, decodedKeyBytes, 0, decodedKeyBytes.length);
                FileOutputStream FOSSYM = openFileOutput("secretKey", Context.MODE_PRIVATE);
                FOSSYM.write(decodedKeyBytes);
                FOSSYM.close();


            } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException | InvalidKeyException e) {
                e.printStackTrace();
            }
        }


        accessToken = new AccessToken();

//        new StartActivity.doHandShake().execute(publicKey, publicKeyServer, privateKey);

        new StartActivity.tryInstaLogin().execute();
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
//    private class doHandShake extends AsyncTask<Key, Void, Response> {
//
//        @Override
//        protected void onPreExecute() {
////            loadingDialog = ProgressDialog.show(HomeActivity.this,
////                    "Please wait...", "Getting data from server");
////            loadingDialog.setCancelable(false);
//        }
//
//        protected Response doInBackground(Key... params) {
//
//            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
//            OkHttpClient client = new OkHttpClient();
//
//            JSONObject jsonBodyParams = new JSONObject();
//            JSONObject jsonBodyParamsEncrypted = new JSONObject();
//
//            /* reado UID from internal memory */
//            try {
//                FileInputStream FISU = openFileInput("UID");
//                InternalFileReader IFR = new InternalFileReader();
//                UIDstring = IFR.readFile(FISU);
//                FISU.close();
//                //Log.i("UID lido", UIDstring);
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//
//            /* insert UID and Base64 encoded User public key in JSON */
//            try {
//                jsonBodyParams.put("userID", UIDstring);
//                jsonBodyParams.put("publicKey", Base64.encodeToString(params[0].getEncoded(), Base64.DEFAULT));
//            } catch (JSONException e) {
//                e.printStackTrace();
//            }
//
//            /* creates symmetric key generator with 256 bit key defined */
//            SecretKey handshakeSecretKey = null;
//            try {
//                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//                keyGenerator.init(256); // AES is currently available in three key sizes: 128, 192 and 256 bits.The design and strength of all key lengths of the AES algorithm are sufficient to protect classified information up to the SECRET level
//                handshakeSecretKey = keyGenerator.generateKey();
//
//            } catch (NoSuchAlgorithmException e) {
//                e.printStackTrace();
//            }
//
//            /* creates key and ciphers JSON using it */
//            String cipherHandshakeString = "";
//            byte[] encryptedHandshake = null;
//            try {
//                byte[] raw = handshakeSecretKey.getEncoded();
//                SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
//                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//                //Log.i("keysizehandshake", String.valueOf(skeySpec.getEncoded().length));
//                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(new byte[16]));
//                byte[] cipherIV = cipher.getIV();
//                String cipherIVString = new String(cipherIV,"UTF-8");
//                //Log.i("IV Length", String.valueOf(cipherIVString.length()));
//                encryptedHandshake = cipher.doFinal((cipherIVString + jsonBodyParams.toString()).getBytes(Charset.forName("UTF-8")));
//                cipherHandshakeString = Base64.encodeToString(encryptedHandshake, Base64.DEFAULT);
//                Log.i("sym key 64", Base64.encodeToString(raw, Base64.DEFAULT));
//
//            } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException e) {
//                e.printStackTrace();
//            } catch (NoSuchAlgorithmException e) {
//                e.printStackTrace();
//            } catch (NoSuchPaddingException e) {
//                e.printStackTrace();
//            } catch (InvalidKeyException e) {
//                e.printStackTrace();
//            }
//
//            /* ciphers previous key usig server public key */
//            byte[] encodedBytes = null;
//            try {
//                Cipher c = Cipher.getInstance("RSA/NONE/OAEPwithSHA-512andMGF1Padding");
//                c.init(Cipher.ENCRYPT_MODE, publicKeyServer);
//                encodedBytes = c.doFinal(handshakeSecretKey.getEncoded());
//            } catch (Exception e) {
//                Log.e("encrypted", "RSA encryption error");
//                e.printStackTrace();
//            }
//
//            /* insert both ciphered texts in new JSON */
//            try {
//                jsonBodyParamsEncrypted.put("data_encrypted", cipherHandshakeString);
//                jsonBodyParamsEncrypted.put("data_encrypted_2", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
//            } catch (JSONException e) {
//                e.printStackTrace();
//            }
//
//            /* send new JSON to server */
//            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParamsEncrypted.toString());
//            Request request = new Request.Builder()
//                    .url(getResources().getString(R.string.handshake))
//                    .header("Content-Type", "application/json")
//                    .post(loginBody)
//                    .build();
//            Log.i("Request header", String.valueOf(request.headers()));
//            Log.i("Request data", String.valueOf(jsonBodyParams.toString()));
//            Log.i("Encrypted data", cipherHandshakeString);
//            Log.i("Encrypted key", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
//            Log.i("Request info", String.valueOf(request));
//            Response response = null;
//
//            try {
//                response = client.newCall(request).execute();
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//
//
//            return response;
//
//        }
//
//        protected void onPostExecute(Response response) {
//
////            loadingDialog.dismiss();
//
//            if (response.isSuccessful()) {
//                JSONObject responseBodyJson = null;
//                String responseString = null;
//
//                String encryptedDataR = "";
//                try {
//                    responseBodyJson = new JSONObject(response.body().string());
//                    encryptedDataR = responseBodyJson.getString("data_encrypted");
//                    Log.i("Encrypted response key", encryptedDataR);
//                } catch (IOException | JSONException e) {
//                    e.printStackTrace();
//                }
//
//                /* decodes and decipher server response to get session symmetric key */
//                byte[] decodedBytesR = null;
//                String decryptedDataR = "";
//                SecretKey secretKey = null;
//                try {
//                    byte[] SYMKEY64 = Base64.decode(encryptedDataR, Base64.DEFAULT);
//                    Cipher d = Cipher.getInstance("RSA/NONE/OAEPwithSHA-512andMGF1Padding");
//                    d.init(Cipher.DECRYPT_MODE, privateKey);
//                    decodedBytesR = d.doFinal(SYMKEY64);
//                    byte[] SYMKEY = Base64.decode(decodedBytesR, Base64.DEFAULT);
//                    //Log.i("decoded key lenght", String.valueOf(SYMKEY.length));
//                    secretKey = new SecretKeySpec(SYMKEY, 0, SYMKEY.length, "AES");
//                    //decryptedDataR = new String(,"UTF-8");
//                    //Log.i("decoded key", decryptedDataR);
//                    Log.i("sym key 64", Base64.encodeToString(secretKey.getEncoded(), Base64.DEFAULT));
//                } catch (Exception e) {
//                    Log.e("decoded", "RSA decryption error");
//                    e.printStackTrace();
//                }
//
//                /* writes session symmetric key to internal memory */
//                try {
//                    FileOutputStream FOSSYM = openFileOutput("secretKey", Context.MODE_PRIVATE);
//                    FOSSYM.write(secretKey.getEncoded());
//                    FOSSYM.close();
//                } catch (IOException e) {
//                    e.printStackTrace();
//                }
//
//            } else {
//
//                Toast toast = Toast.makeText(StartActivity.this,
//                        "Something went wrong, try again later", Toast.LENGTH_SHORT);
//                toast.show();
//                Log.i("response handshake", response.toString());
//                Log.i("response handshake", response.body().toString());
//
//            }
//            new StartActivity.tryInstaLogin().execute();
//
//        }
//    }

}
