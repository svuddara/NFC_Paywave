package nfc.visa.com.nfc.service;

/**
 * Account Parameters
 * Per section 6.3.4
 * <p/>
 * Account Parameters Index
 * Track 2 Equivalent Data
 * Limited Use Key
 */

public class AccountParameters {

    private static byte[] AP_AccountParametersIndex = null;

    private static byte[] AP_T2ED = null;

    private static byte[] AP_LUK = null;

    /**
     * Get the Account Parameters Index
     *
     * @return
     */
    public static byte[] getAccountParametersIndex() {
        return AP_AccountParametersIndex;
    }

    /**
     * Set the Account Parameters Index
     *
     * @param keyString
     */
    public static void setAccountParametersIndex(String keyString) {
        AP_AccountParametersIndex = Util.convertToBytes(keyString, "", 16);
    }

    /**
     * Get the Track2 Equivalent Data
     *
     * @return
     */
    public static byte[] getT2ED() {
        return AP_T2ED;
    }

    /**
     * Set the Track2 Equivalent Data
     *
     * @param keyString
     */
    public static void setT2ED(String keyString) {
        AP_T2ED = Util.convertToBytes(keyString, "", 16);
    }

    /**
     * Retrieve the Limited Use Key
     *
     * @return
     */
    public static byte[] getLUK() {
        return AP_LUK;
    }

    /**
     * Set the Limited Use Key
     *
     * @param keyString
     */
    public static void setLUK(String keyString) {
        AP_LUK = Util.convertToBytes(keyString, "", 16);
    }
}