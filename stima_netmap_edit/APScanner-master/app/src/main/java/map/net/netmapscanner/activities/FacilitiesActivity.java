package map.net.netmapscanner.activities;

import android.app.ProgressDialog;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.design.widget.FloatingActionButton;
import android.support.v7.app.AppCompatActivity;
import android.text.InputType;
import android.view.ContextMenu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ImageButton;
import android.widget.ListView;
import android.widget.Toast;

import com.afollestad.materialdialogs.DialogAction;
import com.afollestad.materialdialogs.MaterialDialog;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import map.net.netmapscanner.R;
import map.net.netmapscanner.classes.facility.Facility;
import map.net.netmapscanner.classes.facility.FacilityAdapter;
import map.net.netmapscanner.utils.GsonUtil;
import map.net.netmapscanner.utils.UserInfo;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class FacilitiesActivity extends AppCompatActivity {

    ListView facilitiesListView;
    FloatingActionButton newFacilityFAB;
    ImageButton reloadFacilitiesButton;

    ProgressDialog loadingDialog;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_facilities);

        reloadFacilitiesButton = (ImageButton) findViewById(R.id.imageButtonReloadFacilities);
        newFacilityFAB = (FloatingActionButton) findViewById(R.id.fabNewFacility);
        facilitiesListView = (ListView) findViewById(R.id.facilitiesListView);

        reloadFacilitiesButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                new getFacilitiesFromServer().execute();
            }
        });

        /* On button's click, calls AsyncTask to send new Facility to server */
        newFacilityFAB.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                MaterialDialog.Builder newFacilityDialog =
                        new MaterialDialog.Builder(FacilitiesActivity.this)
                                .title("Create a new facility")
                                .positiveText("Ok")
                                .negativeText("Cancel")
                                .inputType(InputType.TYPE_CLASS_TEXT)
                                .onPositive(new MaterialDialog.SingleButtonCallback() {
                                    @Override
                                    public void onClick(@NonNull MaterialDialog dialog,
                                                        @NonNull DialogAction which) {

                                        assert dialog.getInputEditText() != null;
                                        String inputText =
                                                dialog.getInputEditText().getText().toString();
                                        new sendFacilityToServer().execute(inputText);
                                    }
                                })
                                .onNegative(new MaterialDialog.SingleButtonCallback() {
                                    @Override
                                    public void onClick(@NonNull MaterialDialog dialog,
                                                        @NonNull DialogAction which) {
                                        dialog.dismiss();
                                    }
                                });

                newFacilityDialog.input("Enter your facility name", null,
                        new MaterialDialog.InputCallback() {
                            @Override
                            public void onInput(@NonNull MaterialDialog dialog, CharSequence input) {

                            }
                        });
                newFacilityDialog.show();
            }
        });

        registerForContextMenu(facilitiesListView);

        new getFacilitiesFromServer().execute();
    }

    @Override
    public void onCreateContextMenu(ContextMenu menu, View v, ContextMenu.ContextMenuInfo menuInfo) {
        super.onCreateContextMenu(menu, v, menuInfo);
        if (v.getId() == R.id.facilitiesListView) {
            MenuInflater inflater = getMenuInflater();
            inflater.inflate(R.menu.facility_menu_list, menu);
        }
    }

    @Override
    public boolean onContextItemSelected(MenuItem item) {
        AdapterView.AdapterContextMenuInfo info = (AdapterView.AdapterContextMenuInfo) item.getMenuInfo();
        switch (item.getItemId()) {
            case R.id.deleteFacility:
                new DeleteFacilityFromServer().run((Facility) facilitiesListView.getItemAtPosition(info.position));
                return true;
            default:
                return super.onContextItemSelected(item);
        }
    }

    /**
     * This async task gets a list of User's facilities data from server and put them into a
     * ListView. The user can touch on the facility to access its zones.
     */
    private class getFacilitiesFromServer extends AsyncTask<Object, Object, Void> {

        @Override
        protected void onPreExecute() {

            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    loadingDialog = ProgressDialog.show(FacilitiesActivity.this,
                            "Please wait...", "Getting data from server");
                    loadingDialog.setCancelable(false);
                }
            });
        }

        @Override
        protected Void doInBackground(Object... params) {

            OkHttpClient client = new OkHttpClient();

            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.get_facilities_url))
                    .header("Content-Type", "application/json")
                    .header("X-User-Email", UserInfo.getUserEmail())
                    .header("X-User-Token", UserInfo.getUserToken())
                    .build();
            Response response = null;

            try {
                response = client.newCall(request).execute();
            } catch (IOException e) {
                e.printStackTrace();
            }


            if (response == null) {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        Toast toast = Toast.makeText(FacilitiesActivity.this,
                                "Something went wrong, try refreshing", Toast.LENGTH_SHORT);
                        toast.show();
                    }
                });
            } else if (response.isSuccessful()) {

                JSONArray facilitiesJSON = null;
                try {
                    facilitiesJSON = new JSONArray(response.body().string());
                } catch (JSONException | IOException e) {
                    e.printStackTrace();
                }

                List<Facility> facilitiesList = new ArrayList<>();

                if (facilitiesJSON != null) {
                    for (int i = 0; i < facilitiesJSON.length(); i++) {
                        try {

                            /* Creates a new Facility object from JSON */
                            JSONObject facilityJSON = facilitiesJSON.getJSONObject(i);
                            Facility facility = new Facility(facilityJSON.get("name").toString());
                            facility.setId(facilityJSON.getJSONObject("_id").get("$oid").toString());

                            /* Sets up a ISO format and convert servers format to it */
                            DateFormat dateFormatISO = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
                            String facilityCreatedAtDate = facilityJSON.get("created_at").toString();
                            Date completeDate = dateFormatISO.parse(facilityCreatedAtDate);

                            /* Setting up days only date*/
                            DateFormat daysOnlyDataFormat = new SimpleDateFormat("dd/MMM/yy", Locale.US);
                            String daysOnlyDate = daysOnlyDataFormat.format(completeDate);
                            facility.setDate(daysOnlyDate);

                            facilitiesList.add(facility);
                        } catch (JSONException | ParseException e) {
                            e.printStackTrace();
                        }
                    }
                }

                final FacilityAdapter adapter = new FacilityAdapter(FacilitiesActivity.this, facilitiesList);

                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        facilitiesListView.setAdapter(adapter);
                        facilitiesListView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                            @Override
                            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                                Facility facilityAtPosition = (Facility) facilitiesListView.getItemAtPosition(position);
                                Intent floorIntent = new Intent(FacilitiesActivity.this, FloorActivity.class);
                                floorIntent.putExtra("FACILITY", facilityAtPosition);
                                startActivity(floorIntent);
                            }
                        });
                    }
                });

            } else {

                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {

                        Toast toast = Toast.makeText(FacilitiesActivity.this,
                                "Something went wrong, try refreshing", Toast.LENGTH_SHORT);
                        toast.show();
                    }
                });
            }


            return null;
        }


        protected void onPostExecute(Void response) {

            loadingDialog.dismiss();


        }
    }

    private class sendFacilityToServer extends AsyncTask<String, Void, Response> {

        @Override
        protected void onPreExecute() {
            loadingDialog = ProgressDialog.show(FacilitiesActivity.this,
                    "Please wait...", "Getting data from server");
            loadingDialog.setCancelable(false);
        }

        @Override
        protected Response doInBackground(String... facilityName) {

            MediaType JSON = MediaType.parse("application/json; charset=utf-8");

            String facilityJSON = GsonUtil.getGson().toJson(new Facility(facilityName[0]));
            RequestBody facilityBody = RequestBody.create(JSON, facilityJSON);

            OkHttpClient client = new OkHttpClient();

            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.new_facility_url))
                    .header("Content-Type", "application/json")
                    .header("X-User-Email", UserInfo.getUserEmail())
                    .header("X-User-Token", UserInfo.getUserToken())
                    .post(facilityBody)
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

            /* Default error message to be shown */
            String defaultErrorMessage = "Something went wrong, try refreshing";

            /* Dismiss dialog*/
            loadingDialog.dismiss();

            /* If, for some reason, the response is null (should not be) */
            if (response == null) {
                Toast toast = Toast.makeText(FacilitiesActivity.this,
                        defaultErrorMessage, Toast.LENGTH_SHORT);
                toast.show();
            }

            /* In this case, server created the facility */
            else if (response.isSuccessful()) {
                new getFacilitiesFromServer().execute();
            }

            /* Response not null, but server rejected */
            else {

                /* Show in toast the error from server */
                try {
                    defaultErrorMessage = response.body().string();
                } catch (IOException e) {
                    e.printStackTrace();
                }

                Toast toast = Toast.makeText(FacilitiesActivity.this,
                        defaultErrorMessage, Toast.LENGTH_SHORT);
                toast.show();
            }

            if (response != null) {
                response.close();
            }
        }

    }

    private class DeleteFacilityFromServer {

        void run(Facility facility) {

            OkHttpClient client = new OkHttpClient();

            HttpUrl deleteFacility_URL = new HttpUrl.Builder()
                    .scheme("http")
                    .host(getString(R.string.urlServer))
                    .port(3000)
                    .addPathSegment("delete_facility")
                    .addQueryParameter("id", facility.getId())
                    .build();

            Request request = new Request.Builder()
                    .url(deleteFacility_URL)
                    .delete()
                    .header("X-User-Email", UserInfo.getUserEmail())
                    .header("X-User-Token", UserInfo.getUserToken())
                    .build();

            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    e.printStackTrace();
                }

                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    if (!response.isSuccessful())
                        throw new IOException("Unexpected code " + response);
                    final String body = response.body().string();
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            Toast toast = null;
                            toast = Toast.makeText(FacilitiesActivity.this,
                                    body, Toast.LENGTH_SHORT);
                            if (toast != null) {
                                toast.show();
                            }
                        }
                    });

                    new getFacilitiesFromServer().execute();
                    response.close();
                }
            });
        }
    }
}

