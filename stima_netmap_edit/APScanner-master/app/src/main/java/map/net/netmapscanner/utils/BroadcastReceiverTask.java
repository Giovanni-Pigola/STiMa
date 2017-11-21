package map.net.netmapscanner.utils;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.CountDownTimer;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import map.net.netmapscanner.classes.access_point.AccessPoint;
import map.net.netmapscanner.classes.acquisition_set.AcquisitionSet;
import map.net.netmapscanner.classes.zone.Zone;

/**
 * This class uses Broadcast Receiver to get wifi data.
 */
public class BroadcastReceiverTask extends AsyncTask<Void, Void, Void> {

    private ProgressDialog scanningDialog;
    private AcquisitionSet mCurrentAcquisitionSet;
    private Normalization mNormalization;
    private int mCurrentCompleteScanNumber = 0;
    private LinkedList<List<ScanResult>> mCache;
    private Context mContext;
    private boolean repeated;
    private Zone mZone;
    private BroadcastReceiver receiver;

    private CountDownTimer thresholdTimer = new CountDownTimer(500,10){
        @Override
        public void onTick(long l) {}
        @Override
        public void onFinish() {
            repeated = false;
        }
    };

    public BroadcastReceiverTask(AcquisitionSet currentAcquisitionSet, Context context, Zone zone) {
        mCurrentAcquisitionSet = currentAcquisitionSet;
        mContext = context;
        mZone = zone;
    }

    @Override
    protected void onPreExecute() {

        scanningDialog = new ProgressDialog(mContext);
        scanningDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
        scanningDialog.setCancelable(false);
        scanningDialog.setIndeterminate(true);
        scanningDialog.setTitle("Scanning...");
        scanningDialog.setMessage("Total scans: " + mCurrentCompleteScanNumber);
        scanningDialog.setButton(DialogInterface.BUTTON_POSITIVE,"Stop", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                mContext.unregisterReceiver(receiver);

                saveToStorage.start();

                Intent intent = ((Activity) mContext).getIntent();
                intent.addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION);
                ((Activity) mContext).finish();
                ((Activity) mContext).overridePendingTransition(0, 0);
                mContext.startActivity(intent);

                dialog.dismiss();
            }
        });

        scanningDialog.show();
    }

    protected void onProgressUpdate(Void... v) {
        scanningDialog.setMessage("Total scans: " + mCurrentCompleteScanNumber);
    }


    @Override
    protected Void doInBackground(Void... voids) {

        mCache = new LinkedList<>();


        final WifiManager wManager = (WifiManager) mContext.getSystemService(Context.WIFI_SERVICE);
        final IntentFilter filter = new IntentFilter();


        filter.addAction(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);

        repeated = false;

        receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if(repeated){
                    thresholdTimer.cancel();
                    thresholdTimer.start();
                }
                else{

                    repeated = true;

                    mCache.add(wManager.getScanResults());

                    mCurrentCompleteScanNumber++;
                    publishProgress();
                }

                wManager.startScan(); // start scan again to get fresh results ASAP

            }
        };

        mContext.registerReceiver(receiver, filter);

        wManager.startScan();

        return null;

    }

    private Thread saveToStorage = new Thread(new Runnable() {
        public void run()
        {
            for (List<ScanResult> measures : mCache){
                ArrayList<AccessPoint> mAccessPointsList = new ArrayList<>();
                for(ScanResult sr : measures){
                    mAccessPointsList.add(new AccessPoint(sr.BSSID, (double) sr.level));
                }
                new SaveAcquisitionSetToFile(mAccessPointsList, mContext, mZone).start();
            }
        }
    });
}
