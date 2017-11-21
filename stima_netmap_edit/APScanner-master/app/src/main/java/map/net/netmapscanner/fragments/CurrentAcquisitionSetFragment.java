package map.net.netmapscanner.fragments;

import android.app.Fragment;
import android.content.Intent;
import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import com.sromku.simple.storage.SimpleStorage;
import com.sromku.simple.storage.Storage;
import com.sromku.simple.storage.helpers.OrderType;

import java.nio.charset.Charset;

import butterknife.BindView;
import butterknife.ButterKnife;
import map.net.netmapscanner.R;
import map.net.netmapscanner.classes.acquisition_set.AcquisitionSet;
import map.net.netmapscanner.classes.zone.Zone;
import map.net.netmapscanner.utils.BroadcastReceiverTask;
import map.net.netmapscanner.utils.CaptureTask;
import map.net.netmapscanner.utils.GsonUtil;

public class CurrentAcquisitionSetFragment extends Fragment {

    @BindView(R.id.currentNormalizationMethod)
    TextView currentNormalizationMethodTextView;

    @BindView(R.id.currentTimeInterval)
    TextView currentTimeIntervalTextView;

    @BindView(R.id.currentScansPerAcquisition)
    TextView currentScansPerAcquisitionTextView;

    @BindView(R.id.currentNumberOfAcquisitions)
    TextView currentNumberOfAcquisitionsTextView;

    @BindView(R.id.fabAddMeasure)
    FloatingActionButton addNewMeasureFAB;

    @BindView(R.id.titleScansPerAcquisition)
    TextView titleScansPerAcquisition;

    @BindView(R.id.titleTimeInterval)
    TextView titleTimeInterval;

    Storage storage;
    Zone zone;


    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {

        Intent i = getActivity().getIntent();
        zone = (Zone) i.getSerializableExtra("zone");

        View view = inflater.inflate(R.layout.current_acquisitions_list_fragment, container, false);
        ButterKnife.bind(this, view);

        storage = SimpleStorage.getInternalStorage(getActivity());

        final AcquisitionSet currentAcquisitionSet = GsonUtil.getGson().fromJson(
                new String(storage.readFile(zone.getName(), "settings"), Charset.forName("UTF-8")),
                AcquisitionSet.class
        );

        currentNormalizationMethodTextView.setText(
                currentAcquisitionSet.getNormalization_algorithm()
        );

        if(!currentAcquisitionSet.getNormalization_algorithm().equals("Continuous scan")){
            currentScansPerAcquisitionTextView.setText(
                    Integer.toString(currentAcquisitionSet.getMeasures_per_point())
            );

            currentTimeIntervalTextView.setText(
                    Float.toString(currentAcquisitionSet.getTime_interval())
            );
        }
        else{
            currentScansPerAcquisitionTextView.setVisibility(View.GONE);
            currentTimeIntervalTextView.setVisibility(View.GONE);
            titleScansPerAcquisition.setVisibility(View.GONE);
            titleTimeInterval.setVisibility(View.GONE);
        }

        currentNumberOfAcquisitionsTextView.setText(
                Integer.toString(storage.getFiles(zone.getName(), OrderType.NAME).size() - 1)
        );

        addNewMeasureFAB.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                AcquisitionSet newAcquisitionSet =
                        new AcquisitionSet(
                                currentAcquisitionSet.getNormalization_algorithm(),
                                currentAcquisitionSet.getTime_interval(),
                                currentAcquisitionSet.getMeasures_per_point()
                        );


                if(currentAcquisitionSet.getNormalization_algorithm().equals("Continuous scan")){
                    BroadcastReceiverTask continuousScan = new BroadcastReceiverTask(
                            newAcquisitionSet,
                            getActivity(),
                            zone);

                    continuousScan.execute();

                }
                else{
                    CaptureTask captureAPs = new CaptureTask(
                            newAcquisitionSet,
                            getActivity(),
                            zone);

                    captureAPs.execute();
                }


                currentNumberOfAcquisitionsTextView.setText(
                        Integer.toString(storage.getFiles(zone.getName(), OrderType.NAME).size() - 1)
                );

            }
        });

        return view;

    }

}
