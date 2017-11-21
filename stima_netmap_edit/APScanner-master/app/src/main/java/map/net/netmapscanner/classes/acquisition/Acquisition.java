package map.net.netmapscanner.classes.acquisition;

import java.io.Serializable;
import java.util.ArrayList;

import map.net.netmapscanner.classes.access_point.AccessPoint;

/**
 * Created by adriano on 05/09/16.
 */
public class Acquisition implements Serializable {

    ArrayList<AccessPoint> accessPointsList;


    public ArrayList<AccessPoint> getAccessPointsList() {
        return accessPointsList;
    }

    public void setAccessPointsList(ArrayList<AccessPoint> accessPointsList) {
        this.accessPointsList = accessPointsList;
    }

    public void addAccessPoint(AccessPoint ap) {
        accessPointsList.add(ap);
    }


}
