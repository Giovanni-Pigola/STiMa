package map.net.netmapscanner.classes.facility;

import com.google.gson.annotations.Expose;

import java.io.Serializable;

public class Facility implements Serializable {

    // Only @Expose variables are used by Gson
    @Expose
    private String name;

    private String date;

    private String id;

    public Facility(String name) {
        this.name = name;
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
}
