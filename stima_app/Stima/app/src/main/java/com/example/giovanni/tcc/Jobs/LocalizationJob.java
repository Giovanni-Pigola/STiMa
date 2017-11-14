package com.example.giovanni.tcc.Jobs;

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.content.Context;
import android.content.Intent;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.util.Log;

import com.example.giovanni.tcc.HomeActivity;
import com.example.giovanni.tcc.Localizacao.AccessPoint;
import com.example.giovanni.tcc.Localizacao.AcquireCurrentZoneFromServer;
import com.example.giovanni.tcc.Localizacao.Normalization;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import okhttp3.OkHttpClient;

import static com.example.giovanni.tcc.HomeActivity.MESSENGER_INTENT_KEY;

import static android.content.ContentValues.TAG;

/**
 * Created by Giovanni on 17/10/2017.
 */

public class LocalizationJob extends JobService {

    private static final String TAG = LocalizationJob.class.getSimpleName();

    private Messenger mActivityMessenger;

    private WifiManager wManager;
    private LinkedList<List<ScanResult>> scanResultsCache;

    private int sampleSize = 3;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "Service created");
        final OkHttpClient client = new OkHttpClient();
        wManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        scanResultsCache = new LinkedList<>();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.i(TAG, "Service destroyed");
    }

    /**
     *
     */
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        mActivityMessenger = intent.getParcelableExtra(MESSENGER_INTENT_KEY);
        return START_NOT_STICKY;
    }

    @Override
    public boolean onStartJob(JobParameters params) {


        if (wManager.startScan()) {
            int x = 0;
            while(x < 3){
                scanResultsCache.add(wManager.getScanResults());
                x++;
            }

            Log.i("scan numero", String.valueOf(scanResultsCache.size()));
            Log.i("sample size", String.valueOf(sampleSize));

            if (scanResultsCache.size() == sampleSize) {

                Normalization normalization = new Normalization("Mean", sampleSize);
                normalization.setOnePointScan(scanResultsCache);
                ArrayList<AccessPoint> nomalisated = normalization.normalize();
                sendMessage(nomalisated);
            }
        }
        scanResultsCache.clear();
        jobFinished(params, false);
        return false;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        return false;
    }

    private void sendMessage(ArrayList<AccessPoint> aquisition) {
        // If this service is launched by the JobScheduler, there's no callback Messenger. It
        // only exists when the MainActivity calls startService() with the callback in the Intent.
        if (mActivityMessenger == null) {
            Log.d(TAG, "Service is bound, not started. There's no callback to send a message to.");
            return;
        }
        Message m = Message.obtain();
        m.obj = aquisition;
        try {
            mActivityMessenger.send(m);
        } catch (RemoteException e) {
            Log.e(TAG, "Error passing service object back to activity.");
        }
    }
}
