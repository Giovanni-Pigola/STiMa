package com.example.giovanni.tcc;

import android.app.ProgressDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.Toast;

import com.example.giovanni.tcc.Auxiliar.DoorAccess;
import com.example.giovanni.tcc.Auxiliar.InternalFileReader;

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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

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

public class LoginActivity extends AppCompatActivity {

    private Button loginButton;
    private ImageView logoCheat;

    private EditText loginEmail;
    private EditText loginSenha;

    private String uniqueID;
    private String facilityID = "";
    private String tagID;

    private FileOutputStream FOSU;
    private FileOutputStream FOST;
    private FileOutputStream FOSR;

    private FileInputStream FIPVTK;
    private FileInputStream FIPBCK;

    private Key publicKey = null;
    private Key privateKey = null;
    private Key publicKeyServer = null;

    private Key publicKeySign = null;
    private Key privateKeySign = null;
    private Key publicKeyServerSign = null;

    private SecretKey secretKey = null;

    private Bundle extras;

    //private ProgressDialog loadingDialog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        loginEmail = (EditText) findViewById(R.id.loginNomeId);
        loginSenha = (EditText) findViewById(R.id.loginSenhaId);

        loginButton = (Button) findViewById(R.id.loginButtonId);
        logoCheat = (ImageView) findViewById(R.id.loginLogoId);

        /* Reads all RSA keys from internal memory */
        try {
            FileInputStream keyPub = openFileInput("publicKey");
            byte[] encKey1 = new byte[keyPub.available()];
            keyPub.read(encKey1);
            keyPub.close();

            //Log.i("len b Public 2", String.valueOf(encKey1.length));
            X509EncodedKeySpec xencoded = new X509EncodedKeySpec(encKey1);
            publicKey = KeyFactory.getInstance("EC").generatePublic(xencoded);
            //Log.i("publicKey", Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT));

            FileInputStream keyPriv = openFileInput("privateKey");
            byte[] encKey2 = new byte[keyPriv.available()];
            keyPriv.read(encKey2);
            keyPriv.close();

            //Log.i("len b Private 2", String.valueOf(encKey2.length));
            PKCS8EncodedKeySpec pkcsencoded = new PKCS8EncodedKeySpec(encKey2);
            privateKey = KeyFactory.getInstance("EC").generatePrivate(pkcsencoded);
            //Log.i("privateKey", Base64.encodeToString(privateKey.getEncoded(), Base64.DEFAULT));

            FileInputStream keyPubS = openFileInput("publicKeyServer");
            byte[] encKey3 = new byte[keyPubS.available()];
            keyPubS.read(encKey3);
            keyPubS.close();

            //Log.i("len b Public Server", String.valueOf(encKey3.length));
            X509EncodedKeySpec pubServerEncoded = new X509EncodedKeySpec(encKey3);
            publicKeyServer = KeyFactory.getInstance("EC").generatePublic(pubServerEncoded);
            //Log.i("server publicKey", Base64.encodeToString(publicKeyServer.getEncoded(), Base64.DEFAULT));

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            Log.i("Keypair", "Keypair not found");
            e.printStackTrace();
        }

        /* reads UID from internal memory */
        try {
            FileInputStream FISU = openFileInput("UID");
            InternalFileReader IFR = new InternalFileReader();
            uniqueID = IFR.readFile(FISU);
            //Log.i("UID lido", uniqueID);
            FISU.close();

        } catch (IOException e) {
            Log.i("entrou aqui", "entrou aqui");
            uniqueID = "";
            e.printStackTrace();
        }


        loginButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                String emailteste = loginEmail.getText().toString();
                String senhateste = loginSenha.getText().toString();

                emailteste = "asd";
                senhateste = "qwerasdf";
                new attemptLogin().execute(emailteste, senhateste);

            }
        });

    }

    /**
     *
     * Attempt Login tries to send the User credentials to the server and receive the token set to be used
     *
     * All communications are made using previously agreed symmetric key using AES256
     *
     * **/
    private class attemptLogin extends AsyncTask<String, Void, Response> {

        @Override
        protected void onPreExecute() {
            /*loadingDialog = ProgressDialog.show(LoginActivity.this,
                    "Please wait...", "Getting data from server");
            loadingDialog.setCancelable(false);*/
        }

        protected Response doInBackground(String... params) {

            String login = params[0];
            String password = params[1];

            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            OkHttpClient client = new OkHttpClient();

            JSONObject jsonBodyParams = new JSONObject();

            /* build credentials JSON */
            try {
                jsonBodyParams.put("username", login);
                jsonBodyParams.put("password", password);
                jsonBodyParams.put("userID", uniqueID);
            } catch (JSONException e) {
                e.printStackTrace();
            }

            /* reads symmetric key from internal memory */
            byte[] SYMKEYb = null;
            try {
                FileInputStream SYMKEY = openFileInput("secretKey");
                SYMKEYb = new byte[SYMKEY.available()];
                SYMKEY.read(SYMKEYb);
                SYMKEY.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

            /* reads symmetric key from internal memory for signature */
            try {
                FileInputStream keyPrivSign = openFileInput("privateKeySign");
                byte[] encKey2Sign = new byte[keyPrivSign.available()];
                keyPrivSign.read(encKey2Sign);
                keyPrivSign.close();

                Log.i("len b Private 2", String.valueOf(encKey2Sign.length));
                PKCS8EncodedKeySpec pkcsencodedSign = new PKCS8EncodedKeySpec(encKey2Sign);
                privateKeySign = KeyFactory.getInstance("EC").generatePrivate(pkcsencodedSign);

                FileInputStream keyPubSign = openFileInput("publicKeySign");
                byte[] encKey1Sign = new byte[keyPubSign.available()];
                keyPubSign.read(encKey1Sign);
                keyPubSign.close();

                Log.i("len b Public 2", String.valueOf(encKey1Sign.length));
                X509EncodedKeySpec xencodedSign = new X509EncodedKeySpec(encKey1Sign);
                publicKeySign = KeyFactory.getInstance("EC").generatePublic(xencodedSign);

                FileInputStream keyPubSSign = openFileInput("publicKeyServerSign");
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
                Log.i("sym key size", String.valueOf(SYMKEYb.length));
                Log.i("sym key 64", Base64.encodeToString(SYMKEYb, Base64.DEFAULT));

                Signature signature = Signature.getInstance("SHA512withECDSA");
                signature.initSign((PrivateKey) privateKeySign);
                signature.update(encodedBytes);
                signed = signature.sign();

                signature.initVerify((PublicKey) publicKeySign);
                signature.update(encodedBytes);
                boolean checksign = signature.verify(signed);
                Log.i("verify signature", String.valueOf(checksign));

//                Log.i("sym key sign size", String.valueOf(publicKeySign.getEncoded().length));
//                Log.i("sym key sign 64", Base64.encodeToString(publicKeySign.getEncoded(), Base64.DEFAULT));
//                Log.i("sym key sign size", String.valueOf(privateKeySign.getEncoded().length));
//                Log.i("sym key sign 64", Base64.encodeToString(privateKeySign.getEncoded(), Base64.DEFAULT));

            } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | SignatureException e) {
                e.printStackTrace();
            }

            /* build new JSON with ciphered texts */
            JSONObject jsonBodyParamsEncrypted = new JSONObject();
            try {
                jsonBodyParamsEncrypted.put("data", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
                jsonBodyParamsEncrypted.put("ECK", Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT));
                jsonBodyParamsEncrypted.put("signature", Base64.encodeToString(signed, Base64.DEFAULT));
                jsonBodyParamsEncrypted.put("ECSK", Base64.encodeToString(publicKeySign.getEncoded(), Base64.DEFAULT));
            } catch (JSONException e) {
                e.printStackTrace();
            }

            /* make request to server */
            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParamsEncrypted.toString());
            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.sign_in_url))
                    .header("Content-Type", "application/json")
                    .post(loginBody)
                    .build();
            Log.i("Request headers", String.valueOf(request.headers()));
            Log.i("Request data", String.valueOf(jsonBodyParams.toString()));
            Log.i("Request data", String.valueOf(jsonBodyParamsEncrypted.toString()));
            Log.i("Encrypted credentials", cipherString);
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

            /*loadingDialog.dismiss();*/

            Log.i("r", String.valueOf(response.isSuccessful()));

            if (response.isSuccessful()) {
                JSONObject responseBodyJson = null;

                /* access token set in memory for further use */
                try {
                    FOST = openFileOutput("JWToken", Context.MODE_PRIVATE);
                    FOSR = openFileOutput("JWRefreshToken", Context.MODE_PRIVATE);
                } catch (FileNotFoundException e) {
                    Log.i("FILE", "FILE NOT FOUND LOGIN2");
                    try {
                        FOST.write(0);
                        FOSR.write(0);
                    } catch (IOException e1) {
                        Log.i("IOE", "LOGIN2");
                        e1.printStackTrace();
                    }
                }

                JSONObject responseBodyJsonEncrypted = null;
                try {
                    responseBodyJsonEncrypted = new JSONObject(response.body().string());
                } catch (JSONException | IOException e) {
                    e.printStackTrace();
                }

                /* get encrypted JSON */
                String stringResponseEncrypted = "";
                String stringResponseSignature = "";
                try {
                    stringResponseEncrypted = responseBodyJsonEncrypted.getString("data");
                    stringResponseSignature = responseBodyJsonEncrypted.getString("signature");
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
                        Log.i("Encrypted response JSON", decipherString);
                    }else {
                        cancel(true);
                    }
                } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | SignatureException e) {
                    e.printStackTrace();
                }

                JSONObject responseBodyJsonDecrypted = null;
                try {
                    responseBodyJsonDecrypted = new JSONObject(decipherString);
                } catch (JSONException e) {
                    e.printStackTrace();
                }

                /* writes token set to internal memory */
                String stringToken = "";
                try {
                    assert responseBodyJsonDecrypted != null;
                    stringToken = responseBodyJsonDecrypted.getString("accessToken");
                    FOST.write(stringToken.getBytes());
                    FOST.close();
                    String stringRefreshToken = responseBodyJsonDecrypted.getString("refreshToken");
                    FOSR.write(stringRefreshToken.getBytes());
                    FOSR.close();
                    Log.i("T", stringToken);
                    Log.i("R", stringRefreshToken);
                } catch (IOException e) {
                    Log.i("IOE", "LOGIN");
                    e.printStackTrace();
                } catch (JSONException e) {
                    e.printStackTrace();
                }

                /* Goes to next activity */
                Intent loginIntent = new Intent(LoginActivity.this, HomeActivity.class);
                startActivity(loginIntent);
                finish();

            } else {

                Toast toast = Toast.makeText(LoginActivity.this,
                        "Something went wrong, try again later", Toast.LENGTH_SHORT);
                toast.show();
                try {
                    throw new IOException("Unexpected code " + response);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
