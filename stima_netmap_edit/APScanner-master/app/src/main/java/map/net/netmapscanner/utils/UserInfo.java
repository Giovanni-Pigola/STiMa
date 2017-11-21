package map.net.netmapscanner.utils;

public class UserInfo {

    private static String mUserEmail;
    private static String mUserToken;

    private UserInfo() {
    }

    public static String getUserEmail() {
        return mUserEmail;
    }

    public static void setUserEmail(String userEmail) {
        mUserEmail = userEmail;
    }

    public static String getUserToken() {
        return mUserToken;
    }

    public static void setUserToken(String userToken) {
        mUserToken = userToken;
    }

}
