package map.net.netmapscanner.classes.zone;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import java.util.List;

import map.net.netmapscanner.R;

public class ZoneAdapter extends ArrayAdapter<Zone> {

    public ZoneAdapter(Context context, List<Zone> objects) {
        super(context, 0, objects);
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        // Get the data item for this position
        Zone zone = getItem(position);
        // Check if an existing view is being reused, otherwise inflate the view
        if (convertView == null) {
            convertView = LayoutInflater.from(getContext()).inflate(R.layout.facility_list_item, parent, false);
        }

        /* Set up elements for view */
        TextView zoneTitle = (TextView) convertView.findViewById(R.id.title);
        zoneTitle.setText(zone.getName());

        TextView zoneSubTitle = (TextView) convertView.findViewById(R.id.subTitle);
        zoneSubTitle.setText(zone.getDate());


        return convertView;
    }
}