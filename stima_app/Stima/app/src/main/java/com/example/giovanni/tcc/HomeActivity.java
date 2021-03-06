package com.example.giovanni.tcc;

import android.app.ProgressDialog;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.CountDownTimer;
import android.os.Handler;
import android.os.Message;
import android.os.Messenger;
import android.os.PersistableBundle;
import android.support.annotation.ColorRes;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.example.giovanni.tcc.Auxiliar.InternalFileReader;
import com.example.giovanni.tcc.Jobs.LocalizationJob;
import com.example.giovanni.tcc.Localizacao.Normalization;
import com.example.giovanni.tcc.Localizacao.ResultResponse;
import com.example.giovanni.tcc.Localizacao.AcquireCurrentZoneFromServer;
import com.example.giovanni.tcc.Security.AccessToken;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.ref.WeakReference;
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
import java.util.LinkedList;
import java.util.List;

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

import static android.Manifest.permission.ACCESS_COARSE_LOCATION;

public class HomeActivity extends AppCompatActivity {

    public static final String MESSENGER_INTENT_KEY
            = BuildConfig.APPLICATION_ID + ".MESSENGER_INTENT_KEY";

    private ImageView airConditioningButton;
    private ImageView lightBulbButton;
    private ImageView calendarButton;
    private ImageView heatMapButton;
    private ImageView userImage;
    private TextView localizacaoStatus;
    private ResultResponse resultResponse;
    private WifiManager wManager;
    private LinkedList<List<ScanResult>> scanResultsCache;
    private AcquireCurrentZoneFromServer acquireCurrentZoneFromServer;
    private Boolean isRequestOver = true;
    private CountDownTimer timer;
    private final int sampleSize = 3;
    private Float updateInterval = 20.0f;
    private static final int REQUEST_ACCESS_LOCATION = 0;
    private String stringLocalizacao = "Localizando...";

    private String tokenLido;
    private String refreshTokenLido;
    private String facilityID = "";

    private ProgressDialog loadingDialog;
    private AccessToken accessToken;

    private FileOutputStream FOJWT;
    private FileOutputStream FOJWR;
    private FileInputStream FID;
    private FileInputStream FJWT;
    private FileInputStream FJWR;

    private SecretKey secretKey = null;

    private Key publicKeySign = null;
    private Key privateKeySign = null;
    private Key publicKeyServerSign = null;

    private int mJobId = 0;
    private static final String TAG = HomeActivity.class.getSimpleName();

    private SharedPreferences pref;



    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_home);

        pref = this.getSharedPreferences("FacilityID", Context.MODE_PRIVATE);

        facilityID = pref.getString("FacilityID","");
        Log.i("autofind", facilityID);

        airConditioningButton = (ImageView) findViewById(R.id.airConditioningId);
        lightBulbButton = (ImageView) findViewById(R.id.lightId);
        calendarButton = (ImageView) findViewById(R.id.calendarId);
        heatMapButton = (ImageView) findViewById(R.id.heatMapId);
        userImage = (ImageView) findViewById(R.id.profileID);
        localizacaoStatus = (TextView) findViewById(R.id.localizacaoStatusID);

        accessToken = new AccessToken();

        /* Inicializacao para Localizacao */
        mayRequestLocationAccess();
        final OkHttpClient client = new OkHttpClient();
        wManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        acquireCurrentZoneFromServer = new AcquireCurrentZoneFromServer();
        Log.i("facility ID HOME", facilityID);
        acquireCurrentZoneFromServer.setFacilityID(facilityID);
        scanResultsCache = new LinkedList<>();
        timer = setTimer(updateInterval, sampleSize, client);
        timer.start();

        /* reads UID from internal memory */
        try {
            InternalFileReader IFR = new InternalFileReader();
            FID = openFileInput("UID");

            FJWT = openFileInput("JWToken");
            tokenLido = IFR.readFile(FJWT);
            //Log.i("tokenlidoHome", tokenLido);
            FJWT.close();

            FJWR = openFileInput("JWRefreshToken");
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

        airConditioningButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                new HomeActivity.getParamAirConditioning().execute(tokenLido);

            }
        });

        lightBulbButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                new HomeActivity.getParamLight().execute(tokenLido);

            }
        });

        calendarButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                new HomeActivity.getGraph().execute(tokenLido);
            }
        });

        heatMapButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                new HomeActivity.getHeatMap().execute(tokenLido);
            }
        });



        localizacaoStatus.setText(stringLocalizacao);

    }

    @Override
    protected void onStart() {
        super.onStart();
        // Start service and provide it a way to communicate with this class.
//        Intent startServiceIntent = new Intent(this, LocalizationJob.class);
//        Messenger messengerIncoming = new Messenger(mHandler);
//        startServiceIntent.putExtra(MESSENGER_INTENT_KEY, messengerIncoming);
//        startService(startServiceIntent);
    }

    @Override
    protected void onStop() {
        SharedPreferences.Editor editor = pref.edit();
        editor.clear();
        editor.apply();
        super.onStop();
    }

    /**
     *
     * Sets the position text view to the acquired position
     *
     * **/
    public void setStringLocalizacao(String local){
        stringLocalizacao = local;
        localizacaoStatus.setText(stringLocalizacao);
    }

    /**
     *
     * Finds air conditioning parameters based on ID sent to server and sends them to the corresponding activity
     *
     * **/
    private class getParamAirConditioning extends AsyncTask<String, Void, Response> {

        @Override
        protected void onPreExecute() {
            loadingDialog = ProgressDialog.show(HomeActivity.this,
                    "Aguarde...", "Carregando configurações de ar condicionado...");
            loadingDialog.setCancelable(false);
        }

        protected Response doInBackground(String... params) {

            String token = params[0];

            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            OkHttpClient client = new OkHttpClient();

//            JSONObject jsonBodyParams = new JSONObject();

            /* puts the air conditioning ID parameters in the first JSON */
//            try {
//                jsonBodyParams.put("acID", "1");
//            } catch (JSONException e) {
//                e.printStackTrace();
//            }

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
//            String cipherString = "";
//            byte[] encodedBytes = null;
//            byte[] signed = null;
//            try {
                secretKey = new SecretKeySpec(SYMKEYb, 0, SYMKEYb.length, "AES");
//                //Log.i("key received length", String.valueOf(SYMKEYb.length));
//                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
//                byte[] cipherIV = cipher.getIV();
//                String cipherIVString = new String(cipherIV,"UTF-8");
//                //Log.i("IV Length", String.valueOf(cipherIVString.length()));
//                encodedBytes = cipher.doFinal((cipherIVString + jsonBodyParams.toString()).getBytes(Charset.forName("UTF-8")));
//                cipherString = Base64.encodeToString(encodedBytes, Base64.DEFAULT);
//                //Log.i("sym key 64", Base64.encodeToString(SYMKEYb, Base64.DEFAULT));
//                //Log.i("sym key 64", cipherString);
//
//                Signature signature = Signature.getInstance("SHA512withECDSA");
//                signature.initSign((PrivateKey) privateKeySign);
//                signature.update(encodedBytes);
//                signed = signature.sign();
//            } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | SignatureException e) {
//                e.printStackTrace();
//            }

            /* build new JSON with ciphered texts */
//            JSONObject jsonBodyParamsEncrypted = new JSONObject();
//            try {
//                jsonBodyParamsEncrypted.put("data", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
//                jsonBodyParamsEncrypted.put("signature", Base64.encodeToString(signed, Base64.DEFAULT));
//            } catch (JSONException e) {
//                e.printStackTrace();
//            }

            /* tests and, if needed, replaces the current Access Token available*/
            try {
                token = accessToken.validaLoginTokenReturn(HomeActivity.this);
            } catch (IOException e) {
                e.printStackTrace();
            }

            /* make request to server */
//            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParamsEncrypted.toString());
            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.air_conditioning_url))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "JWT " + token)
                    .get()
                    .build();
            Log.i("request", String.valueOf(request.headers()));
//            Log.i("request", String.valueOf(jsonBodyParams.toString()));
            Log.i("request", String.valueOf(request));
            Response response = null;

            try {
                response = client.newCall(request).execute();
            } catch (IOException e) {
                e.printStackTrace();
            }

            return response;
        }

        protected void onPostExecute(Response response) {

            loadingDialog.dismiss();

            String acID = "";
            String acIsTurnedOn = "";
            String temperatura = "";
            String fanSpeed= "";
            String humidity = "";
            String zona = "";
            String acParams = "";

            if (response.isSuccessful()) {
                JSONObject responseBodyJsonEncrypted = null;

                try {
                    responseBodyJsonEncrypted = new JSONObject(response.body().string());
                } catch (IOException | JSONException e) {
                    e.printStackTrace();
                }

                /* get encrypted JSON */
                String stringResponseEncrypted = "";
                String stringResponseSignature = "";
                try {
                    stringResponseEncrypted = responseBodyJsonEncrypted.getString("data");
                    stringResponseSignature = responseBodyJsonEncrypted.getString("signature");
                    Log.i("enc response signature", stringResponseSignature);
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
                        decipherString = new String(decodedBytes,"UTF-8");
                        //Log.i("tokens json", decipherString);
                    }else {
                        cancel(true);
                    }
                } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | SignatureException e) {
                    e.printStackTrace();
                }

                JSONObject mainObject = null;
                try {
                    mainObject = new JSONObject(decipherString);
                } catch (JSONException e) {
                    e.printStackTrace();
                }

                /* get all parameters from server response JSON */
                try {
                    acID = mainObject.getString("acID");
                    acIsTurnedOn = mainObject.getString("acIsTurnedOn");
                    temperatura = mainObject.getString("acTemp");
                    fanSpeed = mainObject.getString("acFanSpeed");
                    humidity = mainObject.getString("acHumidity");
                    zona = mainObject.getString("acZone");
                } catch (JSONException e) {
                    e.printStackTrace();
                }

                Toast.makeText(HomeActivity.this, acID, Toast.LENGTH_SHORT).show();

                /* transmits Air Conditioning parameters to Air Conditioning activity */
                Intent airIntent = new Intent(HomeActivity.this, ArCondicionadoActivity.class);
                airIntent.putExtra("acID", acID);
                airIntent.putExtra("acIsTurnedOn", acIsTurnedOn);
                airIntent.putExtra("temperatura", temperatura);
                airIntent.putExtra("fanSpeed", fanSpeed);
                airIntent.putExtra("humidity", humidity);
                airIntent.putExtra("zona", zona);
                startActivity(airIntent);

                //Toast.makeText(HomeActivity.this, "printou aqui " + temperatura, Toast.LENGTH_SHORT).show();

            } else {

                /* sends user back to login page in case token verification fails */
                Intent reLogin = new Intent(HomeActivity.this, LoginActivity.class);

                Toast toast = Toast.makeText(HomeActivity.this,
                        "Something went wrong, try again later", Toast.LENGTH_SHORT);
                toast.show();
                Log.i("responseAC", response.toString());

                startActivity(reLogin);
                finish();
            }

        }
    }

    /**
     *
     * Finds lighting parameters based on ID sent to server and sends them to the corresponding activity
     *
     * **/
    private class getParamLight extends AsyncTask<String, Void, Response> {

        @Override
        protected void onPreExecute() {
            loadingDialog = ProgressDialog.show(HomeActivity.this,
                    "Aguarde...", "Carregando configurações de iluminação...");
            loadingDialog.setCancelable(false);
        }

        protected Response doInBackground(String... params) {

            String token = params[0];

            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            OkHttpClient client = new OkHttpClient();

//            JSONObject jsonBodyParams = new JSONObject();

            /* puts the light ID parameters in the first JSON */
//            try {
//                jsonBodyParams.put("lightID", "1");
//            } catch (JSONException e) {
//                e.printStackTrace();
//            }

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
//            String cipherString = "";
//            byte[] encodedBytes = null;
//            byte[] signed = null;
//            try {
                secretKey = new SecretKeySpec(SYMKEYb, 0, SYMKEYb.length, "AES");
//                //Log.i("key received length", String.valueOf(SYMKEYb.length));
//                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
//                byte[] cipherIV = cipher.getIV();
//                String cipherIVString = new String(cipherIV,"UTF-8");
//                //Log.i("IV Length", String.valueOf(cipherIVString.length()));
//                encodedBytes = cipher.doFinal((cipherIVString + jsonBodyParams.toString()).getBytes(Charset.forName("UTF-8")));
//                cipherString = Base64.encodeToString(encodedBytes, Base64.DEFAULT);
//                //Log.i("sym key 64", Base64.encodeToString(SYMKEYb, Base64.DEFAULT));
//                //Log.i("sym key 64", cipherString);
//
//                Signature signature = Signature.getInstance("SHA512withECDSA");
//                signature.initSign((PrivateKey) privateKeySign);
//                signature.update(encodedBytes);
//                signed = signature.sign();
//            } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | SignatureException e) {
//                e.printStackTrace();
//            }

            /* build new JSON with ciphered texts */
//            JSONObject jsonBodyParamsEncrypted = new JSONObject();
//            try {
//                jsonBodyParamsEncrypted.put("data", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
//                jsonBodyParamsEncrypted.put("signature", Base64.encodeToString(signed, Base64.DEFAULT));
//            } catch (JSONException e) {
//                e.printStackTrace();
//            }

            /* tests and, if needed, replaces the current Access Token available*/
            try {
                token = accessToken.validaLoginTokenReturn(HomeActivity.this);
            } catch (IOException e) {
                e.printStackTrace();
            }

            /* make request to server */
//            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParamsEncrypted.toString());
            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.ligh_url))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "JWT " + token)
                    .get()
                    .build();
            Log.i("request", String.valueOf(request.headers()));
//            Log.i("request", String.valueOf(jsonBodyParams.toString()));
            Log.i("request", String.valueOf(request));
            Response response = null;



            try {
                response = client.newCall(request).execute();
            } catch (IOException e) {
                e.printStackTrace();
            }


            return response;

        }

        protected void onPostExecute(Response response) {

            loadingDialog.dismiss();

            String lightID = "";
            String lightIsTurnedOn = "";
            String lightIntensity = "";
            String lightZone= "";
            String lightParams = "";

            if (response.isSuccessful()) {


                JSONObject responseBodyJsonEncrypted = null;

                try {
                    responseBodyJsonEncrypted = new JSONObject(response.body().string());
                } catch (IOException | JSONException e) {
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
                        //Log.i("tokens json", decipherString);
                    } else{
                        cancel(true);
                    }
                } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | SignatureException e) {
                    e.printStackTrace();
                }

                JSONObject mainObject = null;
                try {
                    mainObject = new JSONObject(decipherString);
                } catch (JSONException e) {
                    e.printStackTrace();
                }

                /* get all parameters from server response JSON */
                try {
                    lightID = mainObject.getString("lightID");
                    lightIsTurnedOn = mainObject.getString("lightIsTurnedOn");
                    lightIntensity = mainObject.getString("lightIntensity");
                    lightZone = mainObject.getString("lightZone");
                } catch (JSONException e) {
                    e.printStackTrace();
                }

                Toast.makeText(HomeActivity.this, lightID, Toast.LENGTH_SHORT).show();

                /* transmits Lighting parameters to Lighting activity */
                Intent lightIntent = new Intent(HomeActivity.this, IluminacaoActivity.class);
                lightIntent.putExtra("lightID", lightID);
                lightIntent.putExtra("lightIsTurnedOn", lightIsTurnedOn);
                lightIntent.putExtra("lightIntensity", lightIntensity);
                lightIntent.putExtra("lightZone", lightZone);
                startActivity(lightIntent);


                //Toast.makeText(HomeActivity.this, "printou aqui " + lightIntensity, Toast.LENGTH_SHORT).show();

            } else {

                /* sends user back to login page in case token verification fails */
                Intent reLogin = new Intent(HomeActivity.this, LoginActivity.class);

                Toast toast = Toast.makeText(HomeActivity.this,
                        "Something went wrong, try again later", Toast.LENGTH_SHORT);
                toast.show();

                startActivity(reLogin);
                finish();
            }

        }
    }

    private class getHeatMap extends AsyncTask<String, Void, Response> {

        @Override
        protected void onPreExecute() {
            loadingDialog = ProgressDialog.show(HomeActivity.this,
                    "Aguarde...", "Gerando mapa de calor.");
            loadingDialog.setCancelable(false);
        }

        protected Response doInBackground(String... strings) {

            String token = strings[0];

            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            OkHttpClient client = new OkHttpClient();

            JSONObject jsonBodyParams = new JSONObject();

            /* puts the light ID parameters in the first JSON */
//            try {
//                jsonBodyParams.put("lightID", "1");
//            } catch (JSONException e) {
//                e.printStackTrace();
//            }
            try {
                jsonBodyParams.put("facility", "Poli Elétrica");
                jsonBodyParams.put("floor", "B2");
                jsonBodyParams.put("type", "mapa");
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
                //Log.i("sym key 64", Base64.encodeToString(SYMKEYb, Base64.DEFAULT));
                //Log.i("sym key 64", cipherString);

                Signature signature = Signature.getInstance("SHA512withECDSA");
                signature.initSign((PrivateKey) privateKeySign);
                signature.update(encodedBytes);
                signed = signature.sign();
            } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | SignatureException e) {
                e.printStackTrace();
            }
//
//            /* build new JSON with ciphered texts */
            JSONObject jsonBodyParamsEncrypted = new JSONObject();
            try {
                jsonBodyParamsEncrypted.put("data", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
                jsonBodyParamsEncrypted.put("signature", Base64.encodeToString(signed, Base64.DEFAULT));
            } catch (JSONException e) {
                e.printStackTrace();
            }

            /* tests and, if needed, replaces the current Access Token available*/
            try {
                token = accessToken.validaLoginTokenReturn(HomeActivity.this);
            } catch (IOException e) {
                e.printStackTrace();
            }

            /* make request to server */
            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParamsEncrypted.toString());
//            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParams.toString());
            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.get_heat_map))
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


            return response;
        }

        protected void onPostExecute(Response response){
            loadingDialog.dismiss();

            Log.i("request", String.valueOf(response));
            if (response.isSuccessful()) {


                Bitmap responseHeatmapImage = null;

                try {
                    responseHeatmapImage = BitmapFactory.decodeStream(response.body().byteStream());

                    FileOutputStream ImgHeatMap = openFileOutput("heatmap", Context.MODE_PRIVATE);
                    responseHeatmapImage.compress(Bitmap.CompressFormat.PNG, 100, ImgHeatMap);
                    ImgHeatMap.close();

                } catch (Exception e) {
                    Log.e("Error", e.getMessage());
                    e.printStackTrace();
                }


                Intent heatMapIntent = new Intent(HomeActivity.this, HeatMap.class);
//                heatMapIntent.putExtra("bitmap", responseHeatmapImage);
                startActivity(heatMapIntent);

                //Toast.makeText(HomeActivity.this, "printou aqui " + lightIntensity, Toast.LENGTH_SHORT).show();

            } else {

                /* sends user back to login page in case token verification fails */
                Intent reLogin = new Intent(HomeActivity.this, LoginActivity.class);

                Toast toast = Toast.makeText(HomeActivity.this,
                        "Something went wrong, try again later", Toast.LENGTH_SHORT);
                toast.show();

                startActivity(reLogin);
                finish();
            }
        }

    }

    private class getGraph extends AsyncTask<String, Void, Response> {

        @Override
        protected void onPreExecute() {
            loadingDialog = ProgressDialog.show(HomeActivity.this,
                    "Aguarde...", "Gerando gráficos.");
            loadingDialog.setCancelable(false);
        }

        protected Response doInBackground(String... strings) {

            String token = strings[0];

            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            OkHttpClient client = new OkHttpClient();

            JSONObject jsonBodyParams = new JSONObject();

            /* puts the light ID parameters in the first JSON */
//            try {
//                jsonBodyParams.put("lightID", "1");
//            } catch (JSONException e) {
//                e.printStackTrace();
//            }
            try {
                jsonBodyParams.put("facility", "Poli Elétrica");
                jsonBodyParams.put("floor", "B2");
                jsonBodyParams.put("type", "pie");
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
                //Log.i("sym key 64", Base64.encodeToString(SYMKEYb, Base64.DEFAULT));
                //Log.i("sym key 64", cipherString);

                Signature signature = Signature.getInstance("SHA512withECDSA");
                signature.initSign((PrivateKey) privateKeySign);
                signature.update(encodedBytes);
                signed = signature.sign();
            } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | SignatureException e) {
                e.printStackTrace();
            }
//
//            /* build new JSON with ciphered texts */
            JSONObject jsonBodyParamsEncrypted = new JSONObject();
            try {
                jsonBodyParamsEncrypted.put("data", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
                jsonBodyParamsEncrypted.put("signature", Base64.encodeToString(signed, Base64.DEFAULT));
            } catch (JSONException e) {
                e.printStackTrace();
            }

            /* tests and, if needed, replaces the current Access Token available*/
            try {
                token = accessToken.validaLoginTokenReturn(HomeActivity.this);
            } catch (IOException e) {
                e.printStackTrace();
            }

            /* make request to server */
            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParamsEncrypted.toString());
//            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParams.toString());
            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.get_heat_map))
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


            return response;
        }

        protected void onPostExecute(Response response){
            loadingDialog.dismiss();

            Log.i("request", String.valueOf(response));
            if (response.isSuccessful()) {

//                Bitmap responseGraphImage = null;
//                try {
//                    responseGraphImage = BitmapFactory.decodeStream(response.body().byteStream());
//
//                    FileOutputStream ImgGraph = openFileOutput("graph", Context.MODE_PRIVATE);
//                    responseGraphImage.compress(Bitmap.CompressFormat.PNG, 100, ImgGraph);
//                    ImgGraph.close();
//
//                } catch (Exception e) {
////                    Log.e("Error", e.getMessage());
//                    e.printStackTrace();
//                }


                Intent heatMapIntent = new Intent(HomeActivity.this, Statistics.class);
//                heatMapIntent.putExtra("bitmap", responseHeatmapImage);
                startActivity(heatMapIntent);

                //Toast.makeText(HomeActivity.this, "printou aqui " + lightIntensity, Toast.LENGTH_SHORT).show();

            } else {

                /* sends user back to login page in case token verification fails */
                Intent reLogin = new Intent(HomeActivity.this, LoginActivity.class);

                Toast toast = Toast.makeText(HomeActivity.this,
                        "Something went wrong, try again later", Toast.LENGTH_SHORT);
                toast.show();

                startActivity(reLogin);
                finish();
            }
        }

    }

    /**
     *
     * Sets timer for interval between positioning checks
     *
     * **/
    public CountDownTimer setTimer(final float totalTime, final int sampleSize, final OkHttpClient client) {

        return new CountDownTimer((long) (totalTime * 1000 / (sampleSize - 1)), (long) totalTime) {

            @Override
            public void onTick(long millisUntilFinished) {
            }

            @Override
            public void onFinish() {

                if (wManager.startScan()) {
                    int x = 0;
                    while(x < 3){
                        scanResultsCache.add(wManager.getScanResults());
                        x++;
                    }

                    isRequestOver = acquireCurrentZoneFromServer.getRequestOver();

                    Log.i("scan numero", String.valueOf(scanResultsCache.size()));
                    Log.i("sample size", String.valueOf(sampleSize));

                    if (scanResultsCache.size() == sampleSize) {

                        Normalization normalization = new Normalization("Mean", sampleSize);
                        normalization.setOnePointScan(scanResultsCache);

                        try {
                            isRequestOver = false;
                            acquireCurrentZoneFromServer.run(client, normalization.normalize(),HomeActivity.this, HomeActivity.this );
                            facilityID = pref.getString("FacilityID","");
                            Log.i("autofind", facilityID);
                            acquireCurrentZoneFromServer.setFacilityID(facilityID);
                            isRequestOver = acquireCurrentZoneFromServer.getRequestOver();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        scanResultsCache.clear();
                        //for (int i = 1; i < sampleSize; i++) {
                        //    scanResultsCache.removeFirst();
                        //}
                    }
                    while(!isRequestOver){
                        try {
                            Thread.sleep(10);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                    this.start();
                }

            }
        };
    }

    /**
     * This function asks for permission to access Coarse Location, necessary to read access points
     * data.
     *
     * @return Boolean telling if ACCESS_COARSE_LOCATION has been permitted (true) or not (false)
     */
    private boolean mayRequestLocationAccess() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return true;
        }
        if (checkSelfPermission(ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED) {
            return true;
        }
        if (shouldShowRequestPermissionRationale(ACCESS_COARSE_LOCATION)) {
            requestPermissions(new String[]{ACCESS_COARSE_LOCATION}, REQUEST_ACCESS_LOCATION);
        } else {
            requestPermissions(new String[]{ACCESS_COARSE_LOCATION}, REQUEST_ACCESS_LOCATION);
        }
        return false;
    }

    /**
     * This function is called by the System after the user has chosen to permit or not
     * Coarse Location to be accessed by the app.
     */
    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        if (requestCode == REQUEST_ACCESS_LOCATION) {
            Intent intent = new Intent(HomeActivity.this, HomeActivity.class);
            startActivity(intent);
            finish();
            overridePendingTransition(0, 0);
        }
    }

}
