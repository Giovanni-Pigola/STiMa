package com.example.giovanni.tcc;

import android.app.ProgressDialog;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.AsyncTask;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.Spinner;
import android.widget.Toast;

import com.example.giovanni.tcc.Auxiliar.InternalFileReader;
import com.example.giovanni.tcc.Security.AccessToken;

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
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

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

public class Statistics extends AppCompatActivity {

    private ImageView mImageView;
    private Spinner spinner1;
    private Spinner spinner2;
    private Button selectFilterButton;

    private ProgressDialog loadingDialog;

    private AccessToken accessToken;

    private String tokenLido;
    private FileInputStream FJWT;

    private SecretKey secretKey = null;

    private Key publicKeySign = null;
    private Key privateKeySign = null;
    private Key publicKeyServerSign = null;

    private String chosenFloor;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_statistics);

        mImageView = (ImageView) findViewById(R.id.graphID);
        spinner1 = (Spinner) findViewById(R.id.spinner3);
        spinner2 = (Spinner) findViewById(R.id.spinner4);
        selectFilterButton = (Button) findViewById(R.id.GraphSelectorButtonID);

        ArrayAdapter<CharSequence> adapter1 = ArrayAdapter.createFromResource(this, R.array.Facilities, android.R.layout.simple_spinner_item);
        adapter1.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner1.setAdapter(adapter1);

        ArrayAdapter<CharSequence> adapter2 = ArrayAdapter.createFromResource(this, R.array.Floors, android.R.layout.simple_spinner_item);
        adapter2.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner2.setAdapter(adapter2);

        accessToken = new AccessToken();

        /* reads UID from internal memory */
        try {
            InternalFileReader IFR = new InternalFileReader();

            FJWT = openFileInput("JWToken");
            tokenLido = IFR.readFile(FJWT);
            //Log.i("tokenlidoHome", tokenLido);
            FJWT.close();

        } catch (FileNotFoundException e) {
            Log.i("FILE", "FILE NOT FOUND HOME");
            e.printStackTrace();
        } catch (IOException e) {
            Log.i("IOE", "HOME");
            e.printStackTrace();
        }

        Bitmap responseGraphImage = null;
//        try {
//            FileInputStream ImgGraph = openFileInput("graph");
//            responseGraphImage = BitmapFactory.decodeStream(ImgGraph);
//
//        } catch (FileNotFoundException e) {
//            e.printStackTrace();
//        }


        mImageView.setImageResource(R.drawable.b2pizza);


        selectFilterButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {

                String chosenFacility = spinner1.getSelectedItem().toString();
                chosenFloor = spinner2.getSelectedItem().toString();
                String type = "pie";

                new Statistics.getGraph().execute(tokenLido, chosenFacility, chosenFloor, type);

            }
        });
    }

    private class getGraph extends AsyncTask<String, Void, Response> {

        @Override
        protected void onPreExecute() {
            loadingDialog = ProgressDialog.show(Statistics.this,
                    "Aguarde...", "Filtrando graficos.");
            loadingDialog.setCancelable(false);
        }

        protected Response doInBackground(String... strings) {

            String token = strings[0];
            String chosenFacilityTask = strings[1];
            String chosenFloorTask = strings[2];
            String typeTask = strings[3];

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
                jsonBodyParams.put("facility", chosenFacilityTask);
                jsonBodyParams.put("floor", chosenFloorTask);
                jsonBodyParams.put("type", typeTask);
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
                token = accessToken.validaLoginTokenReturn(Statistics.this);
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
                if (Objects.equals(chosenFloor, "B2")){
                    mImageView.setImageResource(R.drawable.b2pizza);
                } else {
                    mImageView.setImageResource(R.drawable.b1pizza);
                }


//                try {
//                    responseGraphImage = BitmapFactory.decodeStream(response.body().byteStream());
//                    mImageView.setImageBitmap(responseGraphImage);
//                    FileOutputStream ImgHeatMap = openFileOutput("heatmap", Context.MODE_PRIVATE);
//                    responseHeatmapImage.compress(Bitmap.CompressFormat.PNG, 100, ImgHeatMap);
//                    ImgHeatMap.close();

//                } catch (Exception e) {
//                    Log.e("Error", e.getMessage());
//                    e.printStackTrace();
//                }


//                Intent heatMapIntent = new Intent(HeatMap.this, HeatMap.class);
////                heatMapIntent.putExtra("bitmap", responseHeatmapImage);
//                startActivity(heatMapIntent);
//                finish();

                //Toast.makeText(HomeActivity.this, "printou aqui " + lightIntensity, Toast.LENGTH_SHORT).show();

            } else {

                /* sends user back to login page in case token verification fails */
                Intent reLogin = new Intent(Statistics.this, LoginActivity.class);

                Toast toast = Toast.makeText(Statistics.this,
                        "Something went wrong, try again later", Toast.LENGTH_SHORT);
                toast.show();

                startActivity(reLogin);
                finish();
            }
        }

    }
}
