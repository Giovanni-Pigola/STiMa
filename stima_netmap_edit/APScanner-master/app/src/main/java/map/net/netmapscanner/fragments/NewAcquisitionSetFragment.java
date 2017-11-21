package map.net.netmapscanner.fragments;

import android.app.Fragment;
import android.content.Intent;
import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.Spinner;

import com.sromku.simple.storage.SimpleStorage;
import com.sromku.simple.storage.Storage;

import butterknife.BindView;
import butterknife.ButterKnife;
import map.net.netmapscanner.R;
import map.net.netmapscanner.classes.acquisition_set.AcquisitionSet;
import map.net.netmapscanner.classes.zone.Zone;
import map.net.netmapscanner.utils.BroadcastReceiverTask;
import map.net.netmapscanner.utils.CaptureTask;
import map.net.netmapscanner.utils.GsonUtil;

public class NewAcquisitionSetFragment extends Fragment {

    @BindView(R.id.fabStartMeasure)
    FloatingActionButton startAcquisitionsButton;
    @BindView(R.id.methodSpinner)
    Spinner methodSpinner;
    @BindView(R.id.editTextNumberOfScans)
    EditText numberOfScansEditText;
    @BindView(R.id.editTextTimeInterval)
    EditText timeIntervalEditText;
    @BindView(R.id.checkBoxContinuous)
    CheckBox checkBoxContinuousMode;


    Zone zone;


    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {

        Intent i = getActivity().getIntent();
        zone = (Zone) i.getSerializableExtra("zone");

        View view = inflater.inflate(R.layout.new_acquisition_set_fragment, container, false);
        ButterKnife.bind(this, view);

        startAcquisitionsButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {

                String method = methodSpinner.getSelectedItem().toString();
                float timeInterval = Float.parseFloat(timeIntervalEditText.getText().toString());
                int numberOfScans = Integer.parseInt(numberOfScansEditText.getText().toString());

                if (checkBoxContinuousMode.isChecked()) {
                    method = getString(R.string.continuous_scan);
                }

                AcquisitionSet currentAcquisitionSet =
                        new AcquisitionSet(
                                method,
                                timeInterval,
                                numberOfScans
                        );

                Storage storage = SimpleStorage.getInternalStorage(getActivity());
                String settings = GsonUtil.getGson().toJson(currentAcquisitionSet);
                storage.createFile(zone.getName(), "settings", settings);


                if (currentAcquisitionSet.getNormalization_algorithm().equals("Continuous scan")) {
                    BroadcastReceiverTask continuousScan = new BroadcastReceiverTask(
                            currentAcquisitionSet,
                            getActivity(),
                            zone);

                    continuousScan.execute();

                } else {
                    CaptureTask captureAPs = new CaptureTask(
                            currentAcquisitionSet,
                            getActivity(),
                            zone);

                    captureAPs.execute();
                }


            }
        });

        checkBoxContinuousMode.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    methodSpinner.setEnabled(false);
                    numberOfScansEditText.setEnabled(false);
                    timeIntervalEditText.setEnabled(false);
                } else {
                    methodSpinner.setEnabled(true);
                    numberOfScansEditText.setEnabled(true);
                    timeIntervalEditText.setEnabled(true);
                }

            }
        });


        return view;

    }


}
