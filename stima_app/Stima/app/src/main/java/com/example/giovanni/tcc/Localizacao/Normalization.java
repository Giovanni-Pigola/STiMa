package com.example.giovanni.tcc.Localizacao;

import android.net.wifi.ScanResult;



import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import map.net.KalmanFilter;

/**
 * Created by adriano on 9/8/16.
 */
public class Normalization {


    private String mMethod;
    private Integer mNumberOfAcquisitons;

    private HashMap<String, ArrayList<Double>> mAcquisitions;

    public Normalization(String method, Integer numberOfAcquisitons) {
        mAcquisitions = new HashMap<>();
        mMethod = method;
        mNumberOfAcquisitons = numberOfAcquisitons;
    }

    /**
     *
     * Extracts relevant information from the array of scans an saves it into the
     * mAcquisitions HashMap
     *
     * @param onePointScans Vector of vectors containing ScanResults
     *
     */
    public void setOnePointScan(LinkedList<List<ScanResult>> onePointScans) {

        ArrayList<Double> rssiList;


        for (List<ScanResult> scan : onePointScans) {
            for (ScanResult accessPoint : scan) {
                rssiList = new ArrayList<>();

                if (mAcquisitions.containsKey(accessPoint.BSSID)) {
                    rssiList = mAcquisitions.get(accessPoint.BSSID);
                }

                rssiList.add((double) accessPoint.level);
                mAcquisitions.put(accessPoint.BSSID, rssiList);
            }

        }

    }

    /**
     * Normalizes all Access Points, using the Normalization Method already set in the constructor
     * <p>
     * Empty RSSI acquisitions are filled with -120.0, default value if an Access Point was out of
     * range.
     *
     * @return ArrayList containing all normalized Access Points
     */
    public ArrayList<AccessPoint> normalize() {

        // Iterates trough all BSSIDs to fill slots in RSSIs
        for (String key : mAcquisitions.keySet()) {
            fillWeakAccessPoints(key);
        }

        ArrayList<AccessPoint> accessPointsList = new ArrayList<>();

        // Checks if user has chosen Kalman Filter as Normalization Method
        if (mMethod.equals("Kalman Filter")) {

            // Iterates trough all BSSIDs to apply the normalization
            for (String key : mAcquisitions.keySet()) {
                Double result = KalmanFilter.kalman(mAcquisitions.get(key));
                accessPointsList.add(new AccessPoint(key, result));
            }
        } else {
            // Iterates trough all BSSIDs to apply the normalization
            for (String key : mAcquisitions.keySet()) {
                Double result = KalmanFilter.mean(mAcquisitions.get(key));
                accessPointsList.add(new AccessPoint(key, result));
            }
        }

        return accessPointsList;
    }


    /**
     * This function helps filling blank RSSI slots in the Access Points List.
     * Slots are filled with -120.0 (basically no signal at all).
     *
     * @param key of current rssiList
     */
    private void fillWeakAccessPoints(String key) {
        if (mAcquisitions.get(key).size() < mNumberOfAcquisitons) {
            mAcquisitions.get(key).add(-120.0);
            fillWeakAccessPoints(key);
        }
    }


}
