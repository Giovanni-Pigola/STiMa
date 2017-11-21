package map.net.netmapscanner.classes.floor;

import android.content.Context;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import java.util.List;

import map.net.netmapscanner.R;

public class FloorAdapter extends ArrayAdapter<Floor> {

    public FloorAdapter(Context context, List<Floor> objects) {
        super(context, 0, objects);
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        // Get the data item for this position
        Floor floor = getItem(position);
        // Check if an existing view is being reused, otherwise inflate the view
        if (convertView == null) {
            convertView = LayoutInflater.from(getContext()).inflate(R.layout.facility_list_item, parent, false);
        }

        /* Set up elements for view */
        TextView floorTitle = (TextView) convertView.findViewById(R.id.title);
        floorTitle.setText(floor.getName());

        TextView floorSubTitle = (TextView) convertView.findViewById(R.id.subTitle);
        floorSubTitle.setText(floor.getDate());


        return convertView;
    }
}