package map.net.netmapscanner.utils;

import android.widget.ImageButton;

import com.sromku.simple.storage.Storage;
import com.sromku.simple.storage.helpers.OrderType;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;

import butterknife.BindView;
import map.net.netmapscanner.R;
import map.net.netmapscanner.classes.zone.Zone;

public class LoadAcquisitionsFromStorage extends Thread {

    @BindView(R.id.imageButtonEraseCurrentSet)
    ImageButton eraseCurrentSetButton;
    @BindView(R.id.imageButtonSendSet)
    ImageButton sendCurrentSetsButton;
    private Storage mStorage;
    private Zone mZone;

    public LoadAcquisitionsFromStorage(Storage storage, Zone zone) {

        mZone = zone;
        mStorage = storage;

    }

    public void run() {

            /* Loads all acquisitions stored in files. */
        List<File> files = mStorage.getFiles(mZone.getName(), OrderType.NAME);
        for (File file : files) {
            try {
                BufferedReader bufferedReader = new BufferedReader(new FileReader(file.getPath()));
                StringBuilder stringBuilder = new StringBuilder();
                String line = bufferedReader.readLine();
                while (line != null) {
                    stringBuilder.append(line);
                    line = bufferedReader.readLine();
                }
                String result = stringBuilder.toString();
                int a = 0;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

}
