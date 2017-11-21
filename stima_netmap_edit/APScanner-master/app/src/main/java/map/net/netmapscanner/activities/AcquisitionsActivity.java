package map.net.netmapscanner.activities;

import android.annotation.SuppressLint;
import android.app.FragmentManager;
import android.app.FragmentTransaction;
import android.app.ProgressDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;

import com.afollestad.materialdialogs.DialogAction;
import com.afollestad.materialdialogs.MaterialDialog;
import com.sromku.simple.storage.SimpleStorage;
import com.sromku.simple.storage.Storage;
import com.sromku.simple.storage.helpers.OrderType;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Objects;

import butterknife.BindView;
import butterknife.ButterKnife;
import map.net.netmapscanner.R;
import map.net.netmapscanner.classes.acquisition_set.AcquisitionSet;
import map.net.netmapscanner.classes.zone.Zone;
import map.net.netmapscanner.fragments.CurrentAcquisitionSetFragment;
import map.net.netmapscanner.fragments.NewAcquisitionSetFragment;
import map.net.netmapscanner.utils.GsonUtil;
import map.net.netmapscanner.utils.UserInfo;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import static android.Manifest.permission.ACCESS_COARSE_LOCATION;

public class AcquisitionsActivity extends AppCompatActivity {

    private static final int REQUEST_ACCESS_LOCATION = 0;


    @BindView(R.id.imageButtonEraseCurrentSet)
    ImageButton eraseCurrentSetButton;

    @BindView(R.id.imageButtonSendSet)
    ImageButton sendCurrentSetsButton;

    @BindView(R.id.subtitleAcquisition)
    TextView subtitleAcquisitionTextView;


    Bundle extras;
    Zone zone;
    Storage storage;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_acquisitions);
        ButterKnife.bind(this);

        // Get data passed from Zone Activity
        extras = getIntent().getExtras();
        if (extras != null) {
            zone = (Zone) extras.get("ZONE");
            if (zone != null) {
                subtitleAcquisitionTextView.setText(zone.getName());
            }
        }


        mayRequestLocationAccess();

        storage = SimpleStorage.getInternalStorage(AcquisitionsActivity.this);

            /* Check if directory already exists. If not, create a new one */
        if (!storage.isDirectoryExists(zone.getName())) {
            storage.createDirectory(zone.getName());
        }

        List<File> files = storage.getFiles(zone.getName(), OrderType.NAME);

        FragmentManager fragmentManager = getFragmentManager();
        FragmentTransaction fragmentTransaction = fragmentManager.beginTransaction();

        getIntent().putExtra("zone", zone);

        if (files.isEmpty()) {
            eraseCurrentSetButton.setVisibility(View.INVISIBLE);
            sendCurrentSetsButton.setVisibility(View.INVISIBLE);

            NewAcquisitionSetFragment newAcquisitionSetFragment =
                    new NewAcquisitionSetFragment();

            fragmentTransaction.add(R.id.mainAcquisitionFragment, newAcquisitionSetFragment);
        } else {
            CurrentAcquisitionSetFragment currentAcquisitionSetFragment =
                    new CurrentAcquisitionSetFragment();

            fragmentTransaction.add(R.id.mainAcquisitionFragment, currentAcquisitionSetFragment);


            eraseCurrentSetButton.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    new MaterialDialog.Builder(AcquisitionsActivity.this)
                            .title("Confirmation")
                            .content("Are you sure you want to erase all Acquisitions?")
                            .positiveText("Yes")
                            .onPositive(new MaterialDialog.SingleButtonCallback() {
                                @Override
                                public void onClick(@NonNull MaterialDialog dialog, @NonNull DialogAction which) {
                                    storage.deleteDirectory(zone.getName());

                                    Intent intent = new Intent(AcquisitionsActivity.this, AcquisitionsActivity.class);
                                    intent.putExtra("ZONE", zone);
                                    startActivity(intent);
                                    finish();
                                    overridePendingTransition(0, 0);
                                }
                            })
                            .negativeText("No")
                            .show();

                }
            });

            sendCurrentSetsButton.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    new sendAcquisitionSet(storage).execute();
                }
            });
        }

        fragmentTransaction.commit();

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
            Intent intent = new Intent(AcquisitionsActivity.this, AcquisitionsActivity.class);
            intent.putExtra("ZONE", zone);
            startActivity(intent);
            finish();
            overridePendingTransition(0, 0);
        }
    }

    public class sendAcquisitionSet extends AsyncTask<Object, Object, Response> {

        private Storage mStorage;
        private ProgressDialog loadingDialog;

        private sendAcquisitionSet(Storage storage) {
            mStorage = storage;
        }


        @Override
        protected void onPreExecute() {
            loadingDialog = ProgressDialog.show(AcquisitionsActivity.this,
                    "Please wait...", "Getting data from server");
            loadingDialog.setCancelable(false);
        }

        @SuppressLint("NewApi")
        @Override
        protected Response doInBackground(Object... params) {
            JSONArray acquisitionsJSONArray = new JSONArray();

            final AcquisitionSet currentAcquisitionSet = GsonUtil.getGson().fromJson(
                    new String(storage.readFile(zone.getName(), "settings"), Charset.forName("UTF-8")),
                    AcquisitionSet.class
            );

            for (File file : mStorage.getFiles(zone.getName(), OrderType.NAME)) {
                if (!Objects.equals(file.getName(), "settings")) {
                    JSONObject accessPointJSON = null;
                    try {
                        accessPointJSON = new JSONObject(new String(
                                storage.readFile(zone.getName(), file.getName()),
                                Charset.forName("UTF-8")
                        ));
                    } catch (JSONException e) {
                        e.printStackTrace();
                    }
                    acquisitionsJSONArray.put(accessPointJSON);
                }
            }
            JSONObject acquisitionJSONObject = new JSONObject();
            JSONObject JSONPostBody = new JSONObject();
            String postBody = null;
            try {
                acquisitionJSONObject.put("zone_id", zone.getId());
                acquisitionJSONObject.put("normalization_algorithm",
                        currentAcquisitionSet.getNormalization_algorithm());
                acquisitionJSONObject.put("time_interval",
                        currentAcquisitionSet.getTime_interval());
                acquisitionJSONObject.put("measures_per_point",
                        currentAcquisitionSet.getMeasures_per_point());
                acquisitionJSONObject.put("acquisitions", acquisitionsJSONArray);

                JSONPostBody.put("acquisition_set", acquisitionJSONObject);
                postBody = JSONPostBody.toString();

            } catch (JSONException e) {
                e.printStackTrace();
            }

            OkHttpClient client = new OkHttpClient();

            MediaType JSON = MediaType.parse("application/json; charset=utf-8");
            RequestBody requestBody = null;

            if (postBody != null) {
                requestBody = RequestBody.create(JSON, postBody);
            }

            Request request = new Request.Builder()
                    .url(getResources().getString(R.string.post_acquisition_set_url))
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
                Toast toast = Toast.makeText(AcquisitionsActivity.this,
                        defaultErrorMessage, Toast.LENGTH_SHORT);
                toast.show();
            }

            /* In this case, server created the acquisition set */
            else if (response.isSuccessful()) {

                storage.deleteDirectory(zone.getName());
                Toast toast = Toast.makeText(AcquisitionsActivity.this,
                        "Success!", Toast.LENGTH_SHORT);
                toast.show();
                Intent intent = new Intent(AcquisitionsActivity.this, AcquisitionsActivity.class);
                intent.putExtra("ZONE", zone);
                startActivity(intent);
                finish();
                overridePendingTransition(0, 0);
            }

            /* Response not null, but server rejected */
            else {

                /* Show in toast the error from server */
                try {
                    defaultErrorMessage = response.body().string();
                } catch (IOException e) {
                    e.printStackTrace();
                }

                Toast toast = Toast.makeText(AcquisitionsActivity.this,
                        defaultErrorMessage, Toast.LENGTH_SHORT);
                toast.show();
            }

            if (response != null) {
                response.close();
            }
        }
    }


}


