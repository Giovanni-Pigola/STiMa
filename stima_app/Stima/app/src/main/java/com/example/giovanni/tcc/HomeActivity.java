package com.example.giovanni.tcc;

import android.app.ProgressDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.CountDownTimer;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.example.giovanni.tcc.Auxiliar.InternalFileReader;
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
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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

    private ImageView airConditioningButton;
    private ImageView lightBulbButton;
    private ImageView calendarButton;
    private ImageView heatMapButton;
    private ImageView userImage;
    private TextView localizacaoStatus;
    private Bundle extras;
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

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_home);

        /* finishes activity on NFC read */
        IntentFilter filter = new IntentFilter();
        filter.addAction("com.hello.action");
        registerReceiver(receiver, filter);

        /* receive facility ID for positioning requests*/
        extras = getIntent().getExtras();
        if(extras!=null){
            facilityID = (String) extras.get("facilityID");
        }

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

                Intent calendarIntent = new Intent(HomeActivity.this, CalendarioActivity.class);
                startActivity(calendarIntent);
            }
        });

        heatMapButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                Intent heatMapIntent = new Intent(HomeActivity.this, MapaDeCalorActivity.class);
                startActivity(heatMapIntent);
            }
        });



        localizacaoStatus.setText(stringLocalizacao);

    }

    /**
     *
     * Listens to the NFC read intent in order to finish other opened activities
     *
     * **/
    BroadcastReceiver receiver = new BroadcastReceiver() {

        @Override
        public void onReceive(Context context, Intent intent) {
            finish();

        }
    };

    /**
     *
     * Calls for the standard finish() function
     *
     * **/
    public void finish() {
        unregisterReceiver(receiver);
        super.finish();
    };

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
                    "Please wait...", "Getting data from server");
            loadingDialog.setCancelable(false);
        }

        protected Response doInBackground(String... params) {

            String token = params[0];

            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            OkHttpClient client = new OkHttpClient();

            JSONObject jsonBodyParams = new JSONObject();

            /* puts the air conditioning ID parameters in the first JSON */
            try {
                jsonBodyParams.put("acID", "1");
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

            /* build new JSON with ciphered texts */
            JSONObject jsonBodyParamsEncrypted = new JSONObject();
            try {
                jsonBodyParamsEncrypted.put("data_encrypted", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
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
            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.air_conditioning_url))
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
                try {
                    stringResponseEncrypted = responseBodyJsonEncrypted.getString("data_encrypted");
                    Log.i("enc response login", stringResponseEncrypted);
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
                    "Please wait...", "Getting data from server");
            loadingDialog.setCancelable(false);
        }

        protected Response doInBackground(String... params) {

            String token = params[0];

            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            OkHttpClient client = new OkHttpClient();

            JSONObject jsonBodyParams = new JSONObject();

            /* puts the light ID parameters in the first JSON */
            try {
                jsonBodyParams.put("lightID", "1");
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

            /* build new JSON with ciphered texts */
            JSONObject jsonBodyParamsEncrypted = new JSONObject();
            try {
                jsonBodyParamsEncrypted.put("data_encrypted", Base64.encodeToString(encodedBytes, Base64.DEFAULT));
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
            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.ligh_url))
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
                try {
                    stringResponseEncrypted = responseBodyJsonEncrypted.getString("data_encrypted");
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
