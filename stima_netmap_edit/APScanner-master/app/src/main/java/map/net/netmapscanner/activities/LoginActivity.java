package map.net.netmapscanner.activities;

import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;

import map.net.netmapscanner.R;
import map.net.netmapscanner.utils.UserInfo;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class LoginActivity extends AppCompatActivity {

    ProgressDialog loadingDialog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        final EditText loginEditText = (EditText) findViewById(R.id.editTextLogin);
        final EditText passwordEditText = (EditText) findViewById(R.id.editTextPassword);

        Button signInButton = (Button) findViewById(R.id.button);

        assert signInButton != null;
        signInButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                assert loginEditText != null;
                String login = loginEditText.getText().toString();
                assert passwordEditText != null;
                String password = passwordEditText.getText().toString();

                new attemptLogin().execute(login, password);
            }
        });
    }


    /**
     * This task attempts to perform login sending user email and password to the server,
     * all made asynchronously.
     * <p/>
     * If server returns a 2xx (Successful) code, the server recognized the email/password and
     * them sent back user's token to access other resources from server. Those informations are
     * stored in Android's Shared Preferences.
     * <p/>
     * If the login is wrong OR server is offline OR anything else went wrong, the app will
     * display an error message Toast.
     */
    private class attemptLogin extends AsyncTask<String, Void, Response> {

        @Override
        protected void onPreExecute() {
            loadingDialog = ProgressDialog.show(LoginActivity.this,
                    "Please wait...", "Getting data from server");
            loadingDialog.setCancelable(false);
        }

        protected Response doInBackground(String... params) {

            String login = params[0];
            String password = params[1];


            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            OkHttpClient client = new OkHttpClient();

            JSONObject jsonBodyParams = new JSONObject();
            JSONObject jsonBody = new JSONObject();


            try {
                jsonBodyParams.put("email", login);
                jsonBodyParams.put("password", password);
                jsonBody.put("user", jsonBodyParams);
            } catch (JSONException e) {
                e.printStackTrace();
            }


            RequestBody loginBody = RequestBody.create(JSON, jsonBody.toString());
            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.sign_in_url))
                    .header("Content-Type", "application/json")
                    .post(loginBody)
                    .build();
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

            if (response.isSuccessful()) {
                JSONObject responseBodyJson = null;
                SharedPreferences sharedPref = getSharedPreferences("userInfo", Context.MODE_PRIVATE);
                SharedPreferences.Editor editor = sharedPref.edit();

                try {
                    responseBodyJson = new JSONObject(response.body().string());
                } catch (JSONException | IOException e) {
                    e.printStackTrace();
                }

                /* Tries to save user data to SharedPreferences */
                try {
                    assert responseBodyJson != null;
                    editor.putString("X-User-Email", responseBodyJson.getString("email"));
                    UserInfo.setUserEmail(responseBodyJson.getString("email"));

                    editor.putString("X-User-Token", responseBodyJson.getString("authentication_token"));
                    UserInfo.setUserToken(responseBodyJson.getString("authentication_token"));

                    editor.putBoolean("logged_in?", true);

                    editor.apply();
                } catch (JSONException e) {
                    e.printStackTrace();
                }

                /* Goes to next activity */
                Intent facilitiesActivity = new Intent(LoginActivity.this, FacilitiesActivity.class);
                startActivity(facilitiesActivity);
                finish();

            } else {

                Toast toast = Toast.makeText(LoginActivity.this,
                        "Something went wrong, try again later", Toast.LENGTH_SHORT);
                toast.show();
            }
        }
    }

}