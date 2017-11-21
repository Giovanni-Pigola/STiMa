package map.net.netmapscanner.utils;

import android.content.Context;
import android.widget.Toast;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sromku.simple.storage.SimpleStorage;
import com.sromku.simple.storage.Storage;

import java.util.ArrayList;

import map.net.netmapscanner.classes.access_point.AccessPoint;
import map.net.netmapscanner.classes.zone.Zone;

/**
 * Created by adriano on 10/5/16.
 * <p>
 * SaveAcquisitionSetToFile converts the ArrayList of Access Points into a structured JSON file.
 * Then, saves it in a folder with the Zone name.
 */

public class SaveAcquisitionSetToFile extends Thread {

    private ArrayList<AccessPoint> mFilteredAcquisition;
    private Storage mStorage;
    private Context mContext;
    private Zone mZone;

    public SaveAcquisitionSetToFile(ArrayList<AccessPoint> filteredAcquisition, Context context, Zone zone) {

        mFilteredAcquisition = filteredAcquisition;
        mContext = context;
        mZone = zone;
        mStorage = SimpleStorage.getInternalStorage(context);
    }

    @Override
    public void run() {


        /* Creating the JSON of the acquisition to be stored */
        JsonObject acquisitionJSON = new JsonObject();
        JsonArray accessPointsJSON = new JsonArray();
        JsonObject accessPointJSON;

        for (AccessPoint ap : mFilteredAcquisition) {
            accessPointJSON = new JsonObject();
            accessPointJSON.addProperty("BSSID", ap.getBSSID());
            accessPointJSON.addProperty("RSSI", ap.getRSSI());

            accessPointsJSON.add(accessPointJSON);
        }

        acquisitionJSON.add("access_points", accessPointsJSON);

         /*
         * Creates a new file with the JSON content.
         * The name of the time is the current Unix time.
         * If file wasn't created for some reason, an error Toast will be displayed.
         */
        if (!mStorage.createFile(mZone.getName(),
                Long.toString(System.currentTimeMillis()), acquisitionJSON.toString())) {
            Toast.makeText(mContext,
                    "Acquisition could not be saved. Check your storage.",
                    Toast.LENGTH_SHORT).show();
        }


    }
}
