package map.net.netmapscanner.classes;

import com.google.gson.annotations.Expose;

import java.io.Serializable;

public class ResultResponse implements Serializable {

    @Expose
    private String ZonaName;
    @Expose
    private String Confidence;

    public ResultResponse() {
    }

    public String getZonaName() {
        return ZonaName;
    }

    public void setZonaName(String zonaName) {
        ZonaName = zonaName;
    }

    public String getConfidence() {
        return Confidence;
    }

    public void setConfidence(String confidence) {
        Confidence = confidence;
    }
}
