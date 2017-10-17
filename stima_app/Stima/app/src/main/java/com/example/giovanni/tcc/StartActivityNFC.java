package com.example.giovanni.tcc;

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
import android.widget.Switch;
import android.widget.Toast;

import com.example.giovanni.tcc.Auxiliar.DoorAccess;
import com.example.giovanni.tcc.Auxiliar.InternalFileReader;
import com.example.giovanni.tcc.Security.AccessToken;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class StartActivityNFC extends AppCompatActivity {

    private AccessToken accessToken;

    private NfcAdapter nfcAdapter;

    //private SharedPreferences sharedPref;
    private FileOutputStream FOID;
    private FileOutputStream FOJWT;
    private FileOutputStream FOJWR;

    private FileInputStream FIS;
    private FileInputStream FID;
    private FileInputStream FJWT;
    private FileInputStream FJWR;

    private String uniqueID;
    private String tokenLido;

    private Key publicKeyServer = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        //setContentView(R.layout.activity_start_nfc);

        Intent local = new Intent();
        local.setAction("com.hello.action");
        sendBroadcast(local);

        /* reads Access Token from internal memory*/
        try {
            InternalFileReader IFR = new InternalFileReader();

            FIS = openFileInput("JWToken");
            tokenLido = IFR.readFile(FIS);
            Log.i("tokenNFC", tokenLido);
            FIS.close();
        } catch (FileNotFoundException e) {
            Log.i("FILE", "NOT FOUND NFC");
            e.printStackTrace();
        } catch (IOException e) {
            Log.i("IOE", "NFC");
            e.printStackTrace();
        }

        /* creates NFC reader adapter */
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if(nfcAdapter == null){
            Toast.makeText(this,
                    "NFC NOT supported on this devices!",
                    Toast.LENGTH_LONG).show();
            finish();
        }else if(!nfcAdapter.isEnabled()){
            Toast.makeText(this,
                    "NFC NOT Enabled!",
                    Toast.LENGTH_LONG).show();
            finish();
        }

        accessToken = new AccessToken();


    }

    @Override
    protected void onResume() {
        super.onResume();

        Intent intent = getIntent();
        String action = intent.getAction();

        /* reads tag and stores tagID */
        if (NfcAdapter.ACTION_TAG_DISCOVERED.equals(action)) {
            Toast.makeText(this,
                    "onResume() - ACTION_TAG_DISCOVERED",
                    Toast.LENGTH_SHORT).show();

            String tagInfo = "";
            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            if(tag == null){
                /**
                 * inserir dialog
                 */
            }else{


                byte[] tagId = tag.getId();
                for(int i=0; i<tagId.length; i++){
                    tagInfo += Integer.toHexString(tagId[i] & 0xFF);
                }
            }

            //sharedPref.getString("JWToken", null);

            new StartActivityNFC.tryOpenDoor().execute(tagInfo, tokenLido);


        }else{
            /*Toast.makeText(this,
                    "onResume() : " + action,
                    Toast.LENGTH_SHORT).show();*/
        }



    }

    /**
     *
     * Try Open Door sends the stored tagID to the server and redirects the User to the corresponding activity
     *
     * **/
    private class tryOpenDoor extends AsyncTask<String, Object, Void> {

        @Override
        protected void onPreExecute() {
            /*loadingDialog = ProgressDialog.show(HomeActivity.this,
                    "Please wait...", "Getting data from server");
            loadingDialog.setCancelable(false);*/
        }

        protected Void doInBackground(String... params) {

            try{
                FileInputStream keyPubS = openFileInput("publicKeyServer");
                byte[] encKey3 = new byte[keyPubS.available()];
                keyPubS.read(encKey3);
                keyPubS.close();

                Log.i("len b Public Server", String.valueOf(encKey3.length));
                X509EncodedKeySpec pubServerEncoded = new X509EncodedKeySpec(encKey3);
                publicKeyServer = KeyFactory.getInstance("RSA").generatePublic(pubServerEncoded);
                Log.i("server publicKey", Base64.encodeToString(publicKeyServer.getEncoded(), Base64.DEFAULT));

            } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
                e.printStackTrace();
            }

            Intent nextActivity;

            /* checks token set and creates memory allocation for Access Token and Refresh Token if there isn't already space */
            Boolean bool;
            try {
                bool = accessToken.validaLogin(StartActivityNFC.this);
            } catch (FileNotFoundException e) {
                Log.i("FILE", "NOT FOUND NFC");
                bool = false;
                try {
                    FOID = openFileOutput("UID", Context.MODE_PRIVATE);
                    FOID.write(0);
                    FOID.close();
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
                Log.i("IOE", "NFC");
                bool = false;
                e.printStackTrace();
            }

            /* checks result of previous validation and redirects User accordingly */
            String tagID = params[0];
            if (bool) {
                Log.i("TOKEN PORTA", "Token Valido");

                /* reads UID from internal memory */
                try {
                    FileInputStream FISU = openFileInput("UID");
                    InternalFileReader IFR = new InternalFileReader();
                    uniqueID = IFR.readFile(FISU);
                    //Log.i("UID lido", uniqueID);
                    FISU.close();

                } catch (IOException e) {
                    uniqueID = "";
                    e.printStackTrace();
                }

                String token = params[1];
                //Log.i("tokenNFC lido", token);

                DoorAccess doorAccess = new DoorAccess();
                Intent intentDoorCheck = doorAccess.testDoor(StartActivityNFC.this, tagID, token, uniqueID, publicKeyServer);


                startActivity(intentDoorCheck);

            } else {
                Log.i("TOKEN PORTA", "Token Invalido");
                nextActivity = new Intent(StartActivityNFC.this, LoginActivity.class);
                nextActivity.putExtra("tagID", tagID);
                nextActivity.putExtra("entry", true);
                startActivity(nextActivity);
            }
            finish();


            return null;
        }

        protected void onPostExecute() {

            //loadingDialog.dismiss();

        }
    }
}
