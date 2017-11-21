package map.net.netmapscanner.classes.facility;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import java.util.List;

import map.net.netmapscanner.R;

public class FacilityAdapter extends ArrayAdapter<Facility> {

    public FacilityAdapter(Context context, List<Facility> objects) {
        super(context, 0, objects);
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        // Get the data item for this position
        Facility facility = getItem(position);
        // Check if an existing view is being reused, otherwise inflate the view
        if (convertView == null) {
            convertView = LayoutInflater.from(getContext()).inflate(R.layout.facility_list_item, parent, false);
        }

        /* Set up elements for view */
        TextView facilityTitle = (TextView) convertView.findViewById(R.id.title);
        facilityTitle.setText(facility.getName());

        TextView facilitySubTitle = (TextView) convertView.findViewById(R.id.subTitle);
        facilitySubTitle.setText(facility.getDate());


        return convertView;
    }
}