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
import android.widget.TextView;
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
import map.net.netmapscanner.classes.floor.Floor;
import map.net.netmapscanner.classes.zone.Zone;
import map.net.netmapscanner.classes.zone.ZoneAdapter;
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

public class ZonesActivity extends AppCompatActivity {

    ListView zonesListView;
    TextView subtitleTextView;
    FloatingActionButton newZoneFAB;

    ProgressDialog loadingDialog;

    Bundle extras;
    Facility facility;
    Floor floor;

    ImageButton trainML;
    ImageButton testML;
    ImageButton reloadZonesImageButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_zones);

        // Get data passed from Facility Activity
        extras = getIntent().getExtras();
        if (extras != null) {
            facility = (Facility) extras.get("FACILITY");
            floor = (Floor) extras.get("FLOOR");
        }

        zonesListView = (ListView) findViewById(R.id.zonesListView);
        subtitleTextView = (TextView) findViewById(R.id.subtitleZone);
        newZoneFAB = (FloatingActionButton) findViewById(R.id.fabNewZone);

        trainML = (ImageButton) findViewById(R.id.imageButtonTrain);
        testML = (ImageButton) findViewById(R.id.imageButtonTest);
        reloadZonesImageButton = (ImageButton) findViewById(R.id.imageButtonReloadZones);

        trainML.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {

                new trainMachineLearningOnServer().execute();
            }
        });

        testML.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {

                Intent testIntent = new Intent(ZonesActivity.this, PredictZoneActivity.class);
                testIntent.putExtra("FACILITY", facility);
                startActivity(testIntent);
            }
        });

        reloadZonesImageButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                new getZonesFromServer().execute();
            }
        });

        subtitleTextView.setText(facility.getName());

        /* On button's click, calls AsyncTask to send new Facility to server */

        newZoneFAB.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {

                MaterialDialog.Builder newZoneDialog =
                        new MaterialDialog.Builder(ZonesActivity.this)
                                .title("Create a new zone")
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
                                        new sendZoneToServer().execute(inputText);
                                    }
                                })
                                .onNegative(new MaterialDialog.SingleButtonCallback() {
                                    @Override
                                    public void onClick(@NonNull MaterialDialog dialog,
                                                        @NonNull DialogAction which) {
                                        dialog.dismiss();
                                    }
                                });


                newZoneDialog.input("Enter your zone name", null,
                        new MaterialDialog.InputCallback() {
                            @Override
                            public void onInput(@NonNull MaterialDialog dialog, CharSequence input) {

                            }
                        });

                newZoneDialog.show();
            }
        });

        registerForContextMenu(zonesListView);

        new getZonesFromServer().execute();
    }

    @Override
    public void onCreateContextMenu(ContextMenu menu, View v, ContextMenu.ContextMenuInfo menuInfo) {
        super.onCreateContextMenu(menu, v, menuInfo);
        if (v.getId() == R.id.zonesListView) {
            MenuInflater inflater = getMenuInflater();
            inflater.inflate(R.menu.zone_menu_list, menu);
        }
    }

    @Override
    public boolean onContextItemSelected(MenuItem item) {
        AdapterView.AdapterContextMenuInfo info = (AdapterView.AdapterContextMenuInfo) item.getMenuInfo();
        switch (item.getItemId()) {
            case R.id.deleteZone:
                new ZonesActivity.DeleteZoneFromServer().run((Zone) zonesListView.getItemAtPosition(info.position));
                return true;
            case R.id.clearZone:
                new ZonesActivity.ClearZoneOnServer().run((Zone) zonesListView.getItemAtPosition(info.position));
                return true;
            default:
                return super.onContextItemSelected(item);
        }
    }


    /**
     * This async task gets a list of Floors's zones data from server and put them into a
     * ListView. The user can touch on the zone to access its measures.
     */
    private class getZonesFromServer extends AsyncTask<Void, Void, Response> {

        @Override
        protected void onPreExecute() {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    loadingDialog = ProgressDialog.show(ZonesActivity.this,
                            "Please wait...", "Getting data from server");
                    loadingDialog.setCancelable(false);
                }
            });
        }

        @Override
        protected Response doInBackground(Void... params) {

            OkHttpClient client = new OkHttpClient();

            /* Build URL with parameters*/
            HttpUrl url = HttpUrl.parse(getResources().getString(R.string.get_zones_url)).newBuilder()
                    .addQueryParameter("facility_id", facility.getId())
                    .addQueryParameter("floor_id", floor.getId())
                    .build();

            /* Build request */
            Request request = new Request.Builder()
                    .url(url)
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
                        Toast toast = Toast.makeText(ZonesActivity.this,
                                "Something went wrong, try refreshing", Toast.LENGTH_SHORT);
                        toast.show();
                    }
                });
            } else if (response.code() >= 200 && response.code() < 300) {

                JSONArray zonesJSON = null;
                try {
                    zonesJSON = new JSONArray(response.body().string());
                } catch (JSONException | IOException e) {
                    e.printStackTrace();
                }

                List<Zone> zonesList = new ArrayList<>();

                assert zonesJSON != null;
                for (int i = 0; i < zonesJSON.length(); i++) {
                    try {
                        JSONObject zoneJSON = zonesJSON.getJSONObject(i);
                        Zone zone = new Zone(zoneJSON.get("name").toString());

                        /* Sets up a ISO format and convert servers format to it */
                        DateFormat dateFormatISO = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ENGLISH);
                        String zoneCreatedAtDate = zoneJSON.get("created_at").toString();
                        Date completeDate = dateFormatISO.parse(zoneCreatedAtDate);

                        /* Setting up days only date*/
                        DateFormat daysOnlyDataFormat = new SimpleDateFormat("dd/MMM/yy", Locale.ENGLISH);
                        String daysOnlyDate = daysOnlyDataFormat.format(completeDate);
                        zone.setDate(daysOnlyDate);

                        zone.setId((String) ((JSONObject) zoneJSON.get("_id")).get("$oid"));

                        zonesList.add(zone);
                    } catch (JSONException | ParseException e) {
                        e.printStackTrace();
                    }
                }

                final ZoneAdapter adapter = new ZoneAdapter(ZonesActivity.this, zonesList);
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        zonesListView.setAdapter(adapter);
                        zonesListView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                            @Override
                            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                                Zone zoneAtPosition = (Zone) zonesListView.getItemAtPosition(position);
                                Intent measuresIntent = new Intent(ZonesActivity.this, AcquisitionsActivity.class);
                                measuresIntent.putExtra("ZONE", zoneAtPosition);
                                startActivity(measuresIntent);
                            }
                        });
                    }
                });

            } else {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        Toast toast = Toast.makeText(ZonesActivity.this,
                                "Something went wrong2, try refreshing", Toast.LENGTH_SHORT);
                        toast.show();
                    }
                });
            }

            if (response != null) {
                response.close();
            }
            return response;
        }


        protected void onPostExecute(Response response) {

//            String defaultErrorMessage = "Something went wrong, try refreshing";
//
//            try {
//                defaultErrorMessage = response.body().string();
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//
//            Toast toast = Toast.makeText(ZonesActivity.this,
//                    defaultErrorMessage, Toast.LENGTH_SHORT);
//            toast.show();

            loadingDialog.dismiss();


        }

    }


    private class sendZoneToServer extends AsyncTask<String, Void, Response> {

        @Override
        protected void onPreExecute() {
            loadingDialog = ProgressDialog.show(ZonesActivity.this,
                    "Please wait...", "Getting data from server");
            loadingDialog.setCancelable(false);
        }

        @Override
        protected Response doInBackground(String... zoneName) {
            MediaType JSON = MediaType.parse("application/json; charset=utf-8");

            Zone zone = new Zone(zoneName[0]);
            zone.setFacility_id(facility.getId());
            zone.setFloor_id(floor.getId());

            String zoneJSON = GsonUtil.getGson().toJson(zone);
            RequestBody zoneBody = RequestBody.create(JSON, zoneJSON);

            OkHttpClient client = new OkHttpClient();

            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.new_zone_url))
                    .header("Content-Type", "application/json")
                    .header("X-User-Email", UserInfo.getUserEmail())
                    .header("X-User-Token", UserInfo.getUserToken())
                    .post(zoneBody)
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

            /* Default error message to be shown */
            String defaultErrorMessage = "Something went wrong, try refreshing";

            /* If, for some reason, the response is null (should not be) */
            if (response == null) {
                Toast toast = Toast.makeText(ZonesActivity.this,
                        defaultErrorMessage, Toast.LENGTH_SHORT);
                toast.show();
                return;
            }

            /* In this case, server created the facility */
            else if (response.code() >= 200 && response.code() < 300) {
                new getZonesFromServer().execute();
            }

            /* Response not null, but server rejected */
            else {

                /* Show in toast the error from server */
                try {
                    defaultErrorMessage = response.body().string();
                } catch (IOException e) {
                    e.printStackTrace();
                }

                Toast toast = Toast.makeText(ZonesActivity.this,
                        defaultErrorMessage, Toast.LENGTH_SHORT);
                toast.show();
            }

            response.close();
        }

    }

    private class trainMachineLearningOnServer extends AsyncTask<Void, Void, Response> {

        @Override
        protected void onPreExecute() {
            loadingDialog = ProgressDialog.show(ZonesActivity.this,
                    "Please wait...", "Training machine learning data sets");
            loadingDialog.setCancelable(false);
        }

        @Override
        protected Response doInBackground(Void... params) {

            HttpUrl prepareML_URL = new HttpUrl.Builder()
                    .scheme("http")
                    .host(getString(R.string.urlServer))
                    .port(2000)
                    .addPathSegment("prepare")
                    .addQueryParameter("facilityID", facility.getId())
                    .build();

            HttpUrl trainML_URL = new HttpUrl.Builder()
                    .scheme("http")
                    .host(getString(R.string.urlServer))
                    .port(2000)
                    .addPathSegment("train")
                    .addQueryParameter("facilityID", facility.getId())
                    .build();

            OkHttpClient client = new OkHttpClient();

            Request prepareRequest = new Request.Builder()
                    .url(prepareML_URL)
                    .header("Content-Type", "application/json")
                    .build();

            Request trainRequest = new Request.Builder()
                    .url(trainML_URL)
                    .header("Content-Type", "application/json")
                    .build();

            Response prepareResponse = null;
            Response trainResponse = null;

            try {
                prepareResponse = client.newCall(prepareRequest).execute();
            } catch (IOException e) {
                e.printStackTrace();
            }

            if (prepareResponse != null && prepareResponse.isSuccessful()) {
                try {
                    prepareResponse.close();
                    trainResponse = client.newCall(trainRequest).execute();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }


            if (trainResponse != null) {
                trainResponse.close();
            }

            return trainResponse;


        }

        protected void onPostExecute(Response response) {

            /* Default error message to be shown */
            String defaultErrorMessage = "Something went wrong, try refreshing";

            /* Dismiss dialog*/
            loadingDialog.dismiss();

            /* If, for some reason, the response is null (should not be) */
            if (response == null) {
                Toast toast = Toast.makeText(ZonesActivity.this,
                        defaultErrorMessage, Toast.LENGTH_SHORT);
                toast.show();
            }

            /* Response OK */
            else if (response.isSuccessful()) {
                Toast toast = Toast.makeText(ZonesActivity.this,
                        "Data set was trained", Toast.LENGTH_SHORT);
                toast.show();
            }

            /* Response not null, but server rejected */
            else {
                Toast toast = Toast.makeText(ZonesActivity.this,
                        defaultErrorMessage, Toast.LENGTH_SHORT);
                toast.show();
            }

            if (response != null) {
                response.close();
            }
        }


    }

    private class DeleteZoneFromServer {

        void run(Zone zone) {

            OkHttpClient client = new OkHttpClient();

            HttpUrl deleteFacility_URL = new HttpUrl.Builder()
                    .scheme("http")
                    .host(getString(R.string.urlServer))
                    .port(3000)
                    .addPathSegment("delete_zone")
                    .addQueryParameter("id", zone.getId())
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
                            toast = Toast.makeText(ZonesActivity.this,
                                    body, Toast.LENGTH_SHORT);
                            if (toast != null) {
                                toast.show();
                            }
                        }
                    });

                    new ZonesActivity.getZonesFromServer().execute();
                    response.close();
                }
            });
        }
    }

    private class ClearZoneOnServer {

        void run(Zone zone) {

            OkHttpClient client = new OkHttpClient();

            HttpUrl deleteFacility_URL = new HttpUrl.Builder()
                    .scheme("http")
                    .host(getString(R.string.urlServer))
                    .port(3000)
                    .addPathSegment("clear_zone")
                    .addQueryParameter("id", zone.getId())
                    .build();

            Request request = new Request.Builder()
                    .url(deleteFacility_URL)
                    .get()
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
                            toast = Toast.makeText(ZonesActivity.this,
                                    body, Toast.LENGTH_SHORT);
                            if (toast != null) {
                                toast.show();
                            }
                        }
                    });

                    response.close();
                    new ZonesActivity.getZonesFromServer().execute();

                }
            });
        }
    }

}
