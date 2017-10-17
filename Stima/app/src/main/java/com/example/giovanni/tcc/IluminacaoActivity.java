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
import android.widget.SeekBar;
import android.widget.Switch;
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

public class IluminacaoActivity extends AppCompatActivity {

    private SeekBar dimmer;
    private Switch lightSwitch;
    private Button apllyChanges;

    private Bundle extras;

    private FileInputStream FIS;
    private String tokenLido;

    private String lightID = "";
    private String lightIsTurnedOn = "";
    private String lightIntensity = "";
    private String lightZone = "";

    private int lightIntensityValue;

    private AccessToken accessToken;

    private FileOutputStream FOJWT;
    private FileInputStream FID;
    private FileInputStream FJWT;
    private FileInputStream FJWR;

    private Boolean bool;

    private ProgressDialog loadingDialog;

    private SecretKey secretKey = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_iluminacao);

        /* finishes activity on NFC read */
        IntentFilter filter = new IntentFilter();
        filter.addAction("com.hello.action");
        registerReceiver(receiver, filter);

        dimmer = (SeekBar) findViewById(R.id.lightDimmerID);
        lightSwitch = (Switch) findViewById(R.id.lightSwitchID);
        apllyChanges = (Button) findViewById(R.id.applyID);

        accessToken = new AccessToken();

        /* reads Access Token from internal memory */
        try {
            FIS = openFileInput("JWToken");
            InternalFileReader IFR = new InternalFileReader();
            tokenLido = IFR.readFile(FIS);
            //Log.i("tokenlidoLight", tokenLido);
            FIS.close();
        } catch (FileNotFoundException e) {
            Log.i("FILE", "FILE NOT FOUND Light");
            e.printStackTrace();
        } catch (IOException e) {
            Log.i("IOE", "Light");
            e.printStackTrace();
        }

        /* get Lighting information sent from home */
        extras = getIntent().getExtras();
        if (extras != null) {
            lightID = (String) extras.get("lightID");
            lightIsTurnedOn = (String) extras.get("lightIsTurnedOn");
            lightIntensity = (String) extras.get("lightIntensity");
            lightZone = (String) extras.get("lightZone");
        }

        if (Boolean.parseBoolean(lightIsTurnedOn)){
            lightIntensityValue = Integer.parseInt(lightIntensity);
            dimmer.setProgress(lightIntensityValue);
        }else {
            dimmer.setProgress(0);
        }

        lightSwitch.setChecked(Boolean.parseBoolean(lightIsTurnedOn));


        dimmer.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            @Override
            public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
                lightIntensityValue = progress;
                lightIntensity = String.valueOf(lightIntensityValue);
            }

            @Override
            public void onStartTrackingTouch(SeekBar seekBar) {

            }

            @Override
            public void onStopTrackingTouch(SeekBar seekBar) {

            }
        });

        lightSwitch.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (lightSwitch.isChecked()){
                    lightIsTurnedOn = "1";
                }else {
                    lightIsTurnedOn = "0";
                }
            }
        });

        apllyChanges.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                new IluminacaoActivity.lightUpdateServer().execute(tokenLido, lightIntensity, lightIsTurnedOn);

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

    private class lightUpdateServer extends AsyncTask<String, Void, Response> {

        @Override
        protected void onPreExecute() {
            loadingDialog = ProgressDialog.show(IluminacaoActivity.this,
                    "Please wait...", "Updating data to server");
            loadingDialog.setCancelable(false);
        }

        protected Response doInBackground(String... params) {

            String token = params[0];
            String intensityUpdate = params[1];
            String turnedOnUpdate = params[2];

//            Boolean turnOn = null;
//            switch (turnedOnUpdate){
//                case "1":
//                    turnOn = true;
//                    break;
//                case "0":
//                    turnOn = false;
//                    break;
//            }

            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            OkHttpClient client = new OkHttpClient();

            JSONObject jsonBodyParams = new JSONObject();

            /* get parameters and build JSON */
            try {
                jsonBodyParams.put("lightID", "1");
                jsonBodyParams.put("lightIsTurnedOn", turnedOnUpdate);
                jsonBodyParams.put("lightIntensity", intensityUpdate);
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
                token = accessToken.validaLoginTokenReturn(IluminacaoActivity.this);
            } catch (IOException e) {
                e.printStackTrace();
            }

            /* make request to server */
            RequestBody loginBody = RequestBody.create(JSON, jsonBodyParamsEncrypted.toString());
            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.ligh_update_url))
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

            if (response.isSuccessful()){
                Toast.makeText(IluminacaoActivity.this, response.toString(), Toast.LENGTH_LONG).show();

                Toast toast = Toast.makeText(IluminacaoActivity.this,
                        "Lighting data updated successfully", Toast.LENGTH_SHORT);
                toast.show();
            }else {
                try {
                    throw new IOException("Unexpected code " + response);
                } catch (IOException e) {
                    e.printStackTrace();
                }

                Toast.makeText(IluminacaoActivity.this, response.toString(), Toast.LENGTH_LONG).show();

                Toast toast = Toast.makeText(IluminacaoActivity.this,
                        "Connection timed out, please log in again", Toast.LENGTH_SHORT);
                toast.show();

                /* sends User back to login if update is not successful*/
                Intent reLogin = new Intent(IluminacaoActivity.this, LoginActivity.class);
                startActivity(reLogin);
            }
        }
    }

}
