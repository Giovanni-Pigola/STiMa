package map.net.netmapscanner.activities;

import android.app.ProgressDialog;
import android.content.Intent;
import android.os.AsyncTask;
import android.support.annotation.NonNull;
import android.support.design.widget.FloatingActionButton;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.InputType;
import android.util.Log;
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
import map.net.netmapscanner.classes.floor.Floor;
import map.net.netmapscanner.classes.floor.FloorAdapter;
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

public class FloorActivity extends AppCompatActivity {

    ListView floorsListView;
    FloatingActionButton newFloorFAB;
    ImageButton reloadFloorsButton;

    Bundle extras;
    Facility facility;

    ProgressDialog loadingDialog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_floor);

        // Get data passed from Facility Activity
        extras = getIntent().getExtras();
        if (extras != null) {
            facility = (Facility) extras.get("FACILITY");
        }

        reloadFloorsButton = (ImageButton) findViewById(R.id.imageButtonReloadFloors);
        newFloorFAB = (FloatingActionButton) findViewById(R.id.fabNewFloor);
        floorsListView = (ListView) findViewById(R.id.floorsListView);

        reloadFloorsButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                new FloorActivity.getFloorsFromServer().execute();
            }
        });

        /* On button's click, calls AsyncTask to send new Floor to server */
        newFloorFAB.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                MaterialDialog.Builder newFloorDialog =
                        new MaterialDialog.Builder(FloorActivity.this)
                                .title("Create a new Floor")
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
                                        new FloorActivity.sendFloorToServer().execute(inputText);
                                    }
                                })
                                .onNegative(new MaterialDialog.SingleButtonCallback() {
                                    @Override
                                    public void onClick(@NonNull MaterialDialog dialog,
                                                        @NonNull DialogAction which) {
                                        dialog.dismiss();
                                    }
                                });

                newFloorDialog.input("Enter your floor name", null,
                        new MaterialDialog.InputCallback() {
                            @Override
                            public void onInput(@NonNull MaterialDialog dialog, CharSequence input) {

                            }
                        });
                newFloorDialog.show();
            }
        });

        registerForContextMenu(floorsListView);

        new FloorActivity.getFloorsFromServer().execute();
    }

    @Override
    public void onCreateContextMenu(ContextMenu menu, View v, ContextMenu.ContextMenuInfo menuInfo) {
        super.onCreateContextMenu(menu, v, menuInfo);
        if (v.getId() == R.id.floorsListView) {
            MenuInflater inflater = getMenuInflater();
            inflater.inflate(R.menu.floor_menu_list, menu);
        }
    }

    @Override
    public boolean onContextItemSelected(MenuItem item) {
        AdapterView.AdapterContextMenuInfo info = (AdapterView.AdapterContextMenuInfo) item.getMenuInfo();
        switch (item.getItemId()) {
            case R.id.deleteFloor:
                new FloorActivity.DeleteFloorFromServer().run((Floor) floorsListView.getItemAtPosition(info.position));
                return true;
            default:
                return super.onContextItemSelected(item);
        }
    }

    /**
     * This async task gets a list of User's floors data from server and put them into a
     * ListView. The user can touch on the floor to access its zones.
     */
    private class getFloorsFromServer extends AsyncTask<Object, Object, Response> {

        @Override
        protected void onPreExecute() {

            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    loadingDialog = ProgressDialog.show(FloorActivity.this,
                            "Please wait...", "Getting data from server");
                    loadingDialog.setCancelable(false);
                }
            });
        }

        @Override
        protected Response doInBackground(Object... params) {

            OkHttpClient client = new OkHttpClient();

            HttpUrl url = HttpUrl.parse(getResources().getString(R.string.get_floors_url)).newBuilder()
                    .addQueryParameter("facility_id", facility.getId())
                    .build();

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
                        Toast toast = Toast.makeText(FloorActivity.this,
                                "Something went wrong, try refreshing", Toast.LENGTH_SHORT);
                        toast.show();
                    }
                });
            } else if (response.isSuccessful()) {

                JSONArray floorsJSON = null;
                try {
                    floorsJSON = new JSONArray(response.body().string());
                } catch (JSONException | IOException e) {
                    e.printStackTrace();
                }

                List<Floor> floorList = new ArrayList<>();

                if (floorsJSON != null) {
                    for (int i = 0; i < floorsJSON.length(); i++) {
                        try {

                            /* Creates a new Floor object from JSON */
                            JSONObject floorJSON = floorsJSON.getJSONObject(i);
                            Floor floor = new Floor(floorJSON.get("name").toString());
                            floor.setId(floorJSON.getJSONObject("_id").get("$oid").toString());

                            /* Sets up a ISO format and convert servers format to it */
                            DateFormat dateFormatISO = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
                            String floorCreatedAtDate = floorJSON.get("created_at").toString();
                            Date completeDate = dateFormatISO.parse(floorCreatedAtDate);

                            /* Setting up days only date*/
                            DateFormat daysOnlyDataFormat = new SimpleDateFormat("dd/MMM/yy", Locale.US);
                            String daysOnlyDate = daysOnlyDataFormat.format(completeDate);
                            floor.setDate(daysOnlyDate);

                            floorList.add(floor);
                        } catch (JSONException | ParseException e) {
                            e.printStackTrace();
                        }
                    }
                }

                final FloorAdapter adapter = new FloorAdapter(FloorActivity.this, floorList);

                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        floorsListView.setAdapter(adapter);
                        floorsListView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                            @Override
                            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                                Floor floorAtPosition = (Floor) floorsListView.getItemAtPosition(position);
                                Intent floorIntent = new Intent(FloorActivity.this, ZonesActivity.class);
                                floorIntent.putExtra("FACILITY", facility);
                                floorIntent.putExtra("FLOOR", floorAtPosition);
                                startActivity(floorIntent);
                            }
                        });
                    }
                });

            } else {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {

                        Toast toast = Toast.makeText(FloorActivity.this,
                                "Something2 went wrong, try refreshing", Toast.LENGTH_SHORT);
                        toast.show();
                    }
                });
            }


            return response;
        }

        protected void onPostExecute(Response response) {

            loadingDialog.dismiss();

        }
    }

    private class sendFloorToServer extends AsyncTask<String, Void, Response> {

        @Override
        protected void onPreExecute() {
            loadingDialog = ProgressDialog.show(FloorActivity.this,
                    "Please wait...", "Getting data from server");
            loadingDialog.setCancelable(false);
        }

        @Override
        protected Response doInBackground(String... floorName) {

            MediaType JSON = MediaType.parse("application/json; charset=utf-8");

            JSONObject infoFloorJSONObject = new JSONObject();

            String floorJSON = floorName[0];
            String floorID = facility.getId();
            String floorBody = null;

            try {
                infoFloorJSONObject.put("name", floorJSON);
                infoFloorJSONObject.put("facility_id", floorID);
                floorBody = infoFloorJSONObject.toString();

            } catch (JSONException e) {
                e.printStackTrace();
            }


            RequestBody requestBody = RequestBody.create(JSON, floorBody);

            OkHttpClient client = new OkHttpClient();

            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.new_floor_url))
                    .header("Content-Type", "application/json")
                    .header("X-User-Email", UserInfo.getUserEmail())
                    .header("X-User-Token", UserInfo.getUserToken())
                    .post(requestBody)
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
                Toast toast = Toast.makeText(FloorActivity.this,
                        defaultErrorMessage, Toast.LENGTH_SHORT);
                toast.show();
            }

            /* In this case, server created the floor */
            else if (response.isSuccessful()) {
                new FloorActivity.getFloorsFromServer().execute();
            }

            /* Response not null, but server rejected */
            else {

                /* Show in toast the error from server */
                try {
                    defaultErrorMessage = response.body().string();
                } catch (IOException e) {
                    e.printStackTrace();
                }

                Toast toast = Toast.makeText(FloorActivity.this,
                        defaultErrorMessage, Toast.LENGTH_SHORT);
                toast.show();
            }

            if (response != null) {
                response.close();
            }
        }

    }

    private class DeleteFloorFromServer {

        void run(Floor floor) {

            OkHttpClient client = new OkHttpClient();

            HttpUrl deleteFloor_URL = new HttpUrl.Builder()
                    .scheme("http")
                    .host(getString(R.string.urlServer))
                    .port(3000)
                    .addPathSegment("delete_floor")
                    .addQueryParameter("id", floor.getId())
                    .build();

            Request request = new Request.Builder()
                    .url(deleteFloor_URL)
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
                            Toast toast;
                            toast = Toast.makeText(FloorActivity.this,
                                    body, Toast.LENGTH_SHORT);
                            if (toast != null) {
                                toast.show();
                            }
                        }
                    });

                    new FloorActivity.getFloorsFromServer().execute();
                    response.close();
                }
            });
        }
    }

}
