package com.example.giovanni.tcc;

import android.app.ProgressDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.AsyncTask;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.example.giovanni.tcc.Auxiliar.InternalFileReader;
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

public class ArCondicionadoActivity extends AppCompatActivity {

    private Button tempMais;
    private Button tempMenos;
    private Button ventoMais;
    private Button ventoMenos;
    private Button umidadeMais;
    private Button umidadeMenos;
    private Button confirma;

    private TextView temperaturaView;

    private ImageView fanSpeedView;
    private ImageView humidityView;

    private Bundle extras;

    private FileInputStream FIS;
    private String tokenLido;

    private int temperatureValue = 0;
    private int fanSpeedValue;
    private int humidityValue;

    private AccessToken accessToken;

    private String acID = "";
    private String acIsTurnedOn = "";
    private String temperatura = "";
    private String fanSpeed = "";
    private String humidity = "";
    private String zona = "";
    private String temperaturaMostrada = "---";

    private FileOutputStream FOJWT;
    private FileInputStream FID;
    private FileInputStream FJWT;
    private FileInputStream FJWR;

    private Boolean bool;

    private Context context;

    private ProgressDialog loadingDialog;

    private SecretKey secretKey = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_ar_condicionado);

        /* finishes activity on NFC read */
        IntentFilter filter = new IntentFilter();
        filter.addAction("com.hello.action");
        registerReceiver(receiver, filter);

        temperaturaView = (TextView) findViewById(R.id.textTemperaturaID);

        fanSpeedView = (ImageView) findViewById(R.id.fanSpeedID);
        humidityView = (ImageView) findViewById(R.id.humidityID);

        tempMais = (Button) findViewById(R.id.tempMaisID);
        tempMenos = (Button) findViewById(R.id.tempMenosID);
        ventoMais = (Button) findViewById(R.id.ventoMaisID);
        ventoMenos = (Button) findViewById(R.id.ventoMenosID);
        umidadeMais = (Button) findViewById(R.id.humidadeMaisID);
        umidadeMenos = (Button) findViewById(R.id.humidadeMenosID);
        confirma = (Button) findViewById(R.id.acConfirmaButtonID);

        accessToken = new AccessToken();

        /* reads access token from internal memory */
        try {
            FIS = openFileInput("JWToken");
            InternalFileReader IFR = new InternalFileReader();
            tokenLido = IFR.readFile(FIS);
            //Log.i("tokenlidoAC", tokenLido);
            FIS.close();
        } catch (FileNotFoundException e) {
            Log.i("FILE", "FILE NOT FOUND AC");
            e.printStackTrace();
        } catch (IOException e) {
            Log.i("IOE", "AC");
            e.printStackTrace();
        }

        /* get AC parameters sent from home */
        extras = getIntent().getExtras();
        if (extras != null){
            acID = (String) extras.get("acID");
            acIsTurnedOn = (String) extras.get("acIsTurnedOn");
            temperatura = (String) extras.get("temperatura");
            fanSpeed = (String) extras.get("fanSpeed");
            humidity = (String) extras.get("humidity");
            zona = (String) extras.get("zona");

        } else {
            //inserir asyncTask de refresh
        }
        if (Boolean.parseBoolean(acIsTurnedOn)){
            temperaturaMostrada = temperatura + "ºC";
        }else {
            temperaturaMostrada = temperaturaMostrada + "ºC";
        }

        fanSpeedValue = Integer.parseInt(fanSpeed);
        //Log.i("fanSpeedValue", String.valueOf(fanSpeedValue));
        humidityValue = Integer.parseInt(humidity);
        //Log.i("humidityValue", String.valueOf(humidityValue));
        temperatureValue = Integer.parseInt(temperatura);

        switch (fanSpeedValue){
            case 1:
                Log.i("aqui certo", "certo");
                fanSpeedView.setImageResource(R.drawable.wind1);
                break;
            case 2:
                fanSpeedView.setImageResource(R.drawable.wind2);
                break;
            case 3:
                fanSpeedView.setImageResource(R.drawable.wind3);
        }

        switch (humidityValue){
            case 1:
                Log.i("aqui certo2", "certo2");
                humidityView.setImageResource(R.drawable.humidity);
                break;
            case 2:
                humidityView.setImageResource(R.drawable.humidity2);
                break;
            case 3:
                humidityView.setImageResource(R.drawable.humidity3);
        }

        temperaturaView.setText(temperaturaMostrada);

        tempMais.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (temperatureValue>=16 && temperatureValue<24){
                    temperatureValue += 1;
                }
                temperatura = String.valueOf(temperatureValue);
                temperaturaMostrada = temperatura + "ºC";
                temperaturaView.setText(temperaturaMostrada);
            }
        });

        tempMenos.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (temperatureValue>16 && temperatureValue<=24){
                    temperatureValue -= 1;
                }
                temperatura = String.valueOf(temperatureValue);
                temperaturaMostrada = temperatura + "ºC";
                temperaturaView.setText(temperaturaMostrada);
            }
        });

        ventoMais.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (fanSpeedValue>=1 && fanSpeedValue<3){
                    fanSpeedValue += 1;
                }
                fanSpeed = String.valueOf(fanSpeedValue);
                switch (fanSpeedValue){
                    case 1:
                        fanSpeedView.setImageResource(R.drawable.wind1);
                        break;
                    case 2:
                        fanSpeedView.setImageResource(R.drawable.wind2);
                        break;
                    case 3:
                        fanSpeedView.setImageResource(R.drawable.wind3);
                }
            }
        });

        ventoMenos.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (fanSpeedValue>1 && fanSpeedValue<=3){
                    fanSpeedValue -= 1;
                }
                fanSpeed = String.valueOf(fanSpeedValue);
                switch (fanSpeedValue){
                    case 1:
                        fanSpeedView.setImageResource(R.drawable.wind1);
                        break;
                    case 2:
                        fanSpeedView.setImageResource(R.drawable.wind2);
                        break;
                    case 3:
                        fanSpeedView.setImageResource(R.drawable.wind3);
                }
            }
        });

        umidadeMais.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (humidityValue>=1 && humidityValue<3){
                    humidityValue += 1;
                }
                humidity = String.valueOf(humidityValue);
                switch (humidityValue){
                    case 1:
                        humidityView.setImageResource(R.drawable.humidity);
                        break;
                    case 2:
                        humidityView.setImageResource(R.drawable.humidity2);
                        break;
                    case 3:
                        humidityView.setImageResource(R.drawable.humidity3);
                }
            }
        });

        umidadeMenos.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (humidityValue>1 && humidityValue<=3){
                    humidityValue -= 1;
                }
                humidity = String.valueOf(humidityValue);
                switch (humidityValue){
                    case 1:
                        humidityView.setImageResource(R.drawable.humidity);
                        break;
                    case 2:
                        humidityView.setImageResource(R.drawable.humidity2);
                        break;
                    case 3:
                        humidityView.setImageResource(R.drawable.humidity3);
                }
            }
        });

        confirma.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {


                new ArCondicionadoActivity.acUpdateServer().execute(tokenLido, temperatura, fanSpeed, humidity);

            }
        });

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

    private class acUpdateServer extends AsyncTask<String, Void, Response> {

        @Override
        protected void onPreExecute() {
//            loadingDialog = ProgressDialog.show(ArCondicionadoActivity.this,
//                    "Please wait...", "Updating data to server");
//            loadingDialog.setCancelable(false);
        }

        protected Response doInBackground(String... params) {

            String token = params[0];
            String temperaturaUpdate = params[1];
            String acFanSpeedUpdate = params[2];
            String humidityUpdate = params[3];


            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            OkHttpClient client = new OkHttpClient();

            JSONObject jsonBodyParams = new JSONObject();

            /* gets parameters and build JSON */
            try {
                jsonBodyParams.put("acID", "1");
                jsonBodyParams.put("acIsTurnedOn", "1");
                jsonBodyParams.put("acTemp", temperaturaUpdate);
                jsonBodyParams.put("acFanSpeed", acFanSpeedUpdate);
                jsonBodyParams.put("acHumidity", humidityUpdate);
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

            /* validates token and, if needed, overwrites it */
            try {
                token = accessToken.validaLoginTokenReturn(ArCondicionadoActivity.this);
            } catch (IOException e) {
                e.printStackTrace();
            }

            /* makes request to server */
            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParamsEncrypted.toString());
            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.air_conditioning_update_url))
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

            //loadingDialog.dismiss();

            if (response.isSuccessful()){
                Toast.makeText(ArCondicionadoActivity.this, response.toString(), Toast.LENGTH_LONG).show();

                Toast toast = Toast.makeText(ArCondicionadoActivity.this,
                        "AC data updated successfully", Toast.LENGTH_SHORT);
                toast.show();

            }else {

                try {
                    throw new IOException("Unexpected code " + response);
                } catch (IOException e) {
                    e.printStackTrace();
                }

                Toast.makeText(ArCondicionadoActivity.this, response.toString(), Toast.LENGTH_LONG).show();

                Toast toast = Toast.makeText(ArCondicionadoActivity.this,
                        "Connection timed out, please log in again", Toast.LENGTH_SHORT);
                toast.show();

                /* sends User back to login if update is not successful*/
                Intent reLogin = new Intent(ArCondicionadoActivity.this, LoginActivity.class);
                startActivity(reLogin);
            }

        }

    }
}
