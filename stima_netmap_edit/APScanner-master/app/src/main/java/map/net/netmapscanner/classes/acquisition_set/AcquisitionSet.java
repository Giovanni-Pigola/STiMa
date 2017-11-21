package map.net.netmapscanner.classes.acquisition_set;

import com.google.gson.annotations.Expose;

import java.io.Serializable;

public class AcquisitionSet implements Serializable {

    @Expose
    private String normalization_algorithm;
    @Expose
    private float time_interval;
    @Expose
    private int measures_per_point;

    public AcquisitionSet(String normalization_algorithm, float time_interval, int measures_per_point) {
        this.normalization_algorithm = normalization_algorithm;
        this.time_interval = time_interval;
        this.measures_per_point = measures_per_point;
    }

    public String getNormalization_algorithm() {
        return normalization_algorithm;
    }

    public void setNormalization_algorithm(String normalization_algorithm) {
        this.normalization_algorithm = normalization_algorithm;
    }

    public float getTime_interval() {
        return time_interval;
    }

    public void setTime_interval(float time_interval) {
        this.time_interval = time_interval;
    }

    public int getMeasures_per_point() {
        return measures_per_point;
    }

    public void setMeasures_per_point(int measures_per_point) {
        this.measures_per_point = measures_per_point;
    }
}
