package map.net.netmapscanner.activities;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.CountDownTimer;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import butterknife.BindView;
import butterknife.ButterKnife;
import map.net.netmapscanner.R;
import map.net.netmapscanner.classes.ResultResponse;
import map.net.netmapscanner.classes.access_point.AccessPoint;
import map.net.netmapscanner.classes.facility.Facility;
import map.net.netmapscanner.utils.Normalization;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import static android.Manifest.permission.ACCESS_COARSE_LOCATION;

public class PredictZoneActivity extends AppCompatActivity {

    private static final int REQUEST_ACCESS_LOCATION = 0;
    final int sampleSize = 3;
    @BindView(R.id.subtitleFacilityName)
    TextView subtitleFacilityName;
    @BindView(R.id.probability)
    TextView confidence;
    @BindView(R.id.zoneName)
    TextView zoneName;
    @BindView(R.id.progressBar)
    ProgressBar progressBar;
    @BindView(R.id.editTextUpdateInterval)
    TextView editTextUpdateInterval;
    @BindView(R.id.button2)
    Button buttonOK;
    Bundle extras;
    Facility facility;
    WifiManager wManager;
    Float updateInterval = 2.0f;
    AcquireCurrentZoneFromServer acquireCurrentZoneFromServer;
    String currentZone = "";
    CountDownTimer timer;
    //This is a "cache" for the scans, so it is possible to be normalized
    LinkedList<List<ScanResult>> scanResultsCache;
    Boolean isRequestOver = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_predict_zone);
        ButterKnife.bind(this);

        mayRequestLocationAccess();

        final OkHttpClient client = new OkHttpClient();
        wManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        acquireCurrentZoneFromServer = new AcquireCurrentZoneFromServer();

        // Get data passed from Zone Activity
        extras = getIntent().getExtras();
        if (extras != null) {
            facility = (Facility) extras.get("FACILITY");
            if (facility != null) {
                subtitleFacilityName.setText(facility.getName());
            }
        }

        // Set progress bar default size
        progressBar.setMax((int) (updateInterval * 1000));

        // Set update time
        buttonOK.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                try {
                    updateInterval = Float.parseFloat(editTextUpdateInterval.getText().toString());
                    if (updateInterval < 0.5f) {
                        updateInterval = 2.0f;
                        editTextUpdateInterval.setText("2.0");
                        Toast toast = Toast.makeText(PredictZoneActivity.this,
                                "Must be greater than 0.5", Toast.LENGTH_SHORT);
                        toast.show();
                    }
                } catch (NumberFormatException e) {
                    updateInterval = 2.0f;
                    editTextUpdateInterval.setText("2.0");
                    Toast toast = Toast.makeText(PredictZoneActivity.this,
                            "Invalid format", Toast.LENGTH_SHORT);
                    toast.show();
                }
                progressBar.setMax((int) (updateInterval * 1000));
                timer.cancel();
                timer = setTimer(updateInterval, sampleSize, client).start();
            }
        });

        /*
        * This part of the code schedules the scan and calls it after the interval suggested
        * by the user. It is called endlessly. It normalizes the input by scanning 3 times.
        */
        scanResultsCache = new LinkedList<>();

        timer = setTimer(updateInterval, sampleSize, client);
        timer.start();
    }

    /**
     * This function finishes the activity after back button is pressed.
     */
    @Override
    public void onBackPressed() {
        super.onBackPressed();
        timer.cancel();
        finish();
    }


    /**
     * This function finishes the activity after the app is sent to background.
     */
    @Override
    protected void onPause() {
        super.onPause();
        timer.cancel();
        finish();
    }

    /**
     * This method creates a new CountDownTimer able to schedule scans and send normalized data
     * to the server
     *
     * @param totalTime  Time defined between HTTP calls and results
     * @param sampleSize Number of samples for arithmetic mean
     * @param client     OkHTTP client
     * @return CountDownTimer ready to send requests at any rate
     **/

    public CountDownTimer setTimer(final float totalTime, final int sampleSize, final OkHttpClient client) {

        return new CountDownTimer((long) (totalTime * 1000 / (sampleSize - 1)), (long) totalTime) {

            @Override
            public void onTick(long millisUntilFinished) {
                progressBar.setProgress((int) (totalTime * 1000 - millisUntilFinished -
                        (sampleSize - scanResultsCache.size() - 1) *
                                (totalTime * 1000 / (sampleSize - 1)))
                );
            }

            @Override
            public void onFinish() {
                if (wManager.startScan()) {
                    scanResultsCache.add(wManager.getScanResults());

                    if (scanResultsCache.size() == sampleSize) {
                        Normalization normalization = new Normalization("Mean", sampleSize);
                        normalization.setOnePointScan(scanResultsCache);

                        try {
                            isRequestOver = false;
                            acquireCurrentZoneFromServer.run(client, normalization.normalize());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        for (int i = 1; i < sampleSize; i++) {
                            scanResultsCache.removeFirst();
                        }
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
            Intent intent = new Intent(PredictZoneActivity.this, PredictZoneActivity.class);
            intent.putExtra("FACILITY", facility);
            startActivity(intent);
            finish();
            overridePendingTransition(0, 0);
        }
    }


    private class AcquireCurrentZoneFromServer {

        void run(OkHttpClient client, ArrayList<AccessPoint> accessPoints) throws Exception {

            JSONObject requestBodyJSON = new JSONObject();
            JSONObject apJSON;
            JSONArray acquisitionsJSONArray = new JSONArray();

            requestBodyJSON.put("facility_id", facility.getId());
            for (AccessPoint ap : accessPoints) {
                apJSON = new JSONObject();
                apJSON.put("BSSID", ap.getBSSID());
                apJSON.put("RSSI", ap.getRSSI());
                acquisitionsJSONArray.put(apJSON);
            }

            requestBodyJSON.put("access_points", acquisitionsJSONArray);
            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            RequestBody requestBody = RequestBody.create(JSON, String.valueOf(requestBodyJSON));

            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.predict_zone_url))
                    .post(requestBody)
                    .build();

            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    e.printStackTrace();

                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            Toast toast = Toast.makeText(PredictZoneActivity.this,
                                    "Something went wrong, try again later", Toast.LENGTH_SHORT);
                            toast.show();
                        }
                    });
                }

                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    if (!response.isSuccessful()) {
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                Toast toast = Toast.makeText(PredictZoneActivity.this,
                                        "Something went wrong, try again later", Toast.LENGTH_SHORT);
                                toast.show();
                            }
                        });
                        throw new IOException("Unexpected code " + response);
                    }

                    currentZone = response.body().string();
                    currentZone = currentZone.substring(2, currentZone.length() - 2);


                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            ResultResponse resultResponse = new ResultResponse();
                            JSONObject jsonObject;
                            try {
                                jsonObject = new JSONObject(currentZone.replace("\\", ""));
                                resultResponse.setZonaName(jsonObject.getString("ZonaName"));
                                resultResponse.setConfidence(String.valueOf(jsonObject.getDouble("Confidence")));
                            } catch (JSONException e) {
                                e.printStackTrace();
                            }


                            zoneName.setText(resultResponse.getZonaName());
                            String placeText = "Confidence: " + resultResponse.getConfidence();
                            confidence.setText(placeText);
                        }
                    });
                    response.close();
                    isRequestOver = true;
                }
            });
        }
    }
}



