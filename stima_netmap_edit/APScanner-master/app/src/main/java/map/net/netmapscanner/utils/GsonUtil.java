package map.net.netmapscanner.utils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Created by adriano on 8/20/16.
 */
public class GsonUtil {

    private static Gson gson;

    public GsonUtil(){
        gson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
    }

    public static Gson getGson() {
        return gson;
    }
}
