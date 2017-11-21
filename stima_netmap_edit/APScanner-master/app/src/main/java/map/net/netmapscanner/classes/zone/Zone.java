package map.net.netmapscanner.classes.zone;

import com.google.gson.annotations.Expose;

import java.io.Serializable;

public class Zone implements Serializable {

    @Expose
    private String name;
    @Expose
    private String facility_id;
    @Expose
    private String floor_id;
    private String date;
    private String id;

    public Zone(String name) {
        this.name = name;
    }

    public String getFloor_id() {
        return floor_id;
    }

    public void setFloor_id(String floor_id) {
        this.floor_id = floor_id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDate() {
        return date;
    }

    public void setDate(String date) {
        this.date = date;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getFacility_id() {
        return facility_id;
    }

    public void setFacility_id(String facility_id) {
        this.facility_id = facility_id;
    }
}
