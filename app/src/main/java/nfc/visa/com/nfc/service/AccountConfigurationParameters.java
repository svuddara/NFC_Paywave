package nfc.visa.com.nfc.service;

/**
 * Account Configuration Parameters
 * Per section 6.3.2
 * <p/>
 * AID
 * CVM(s) supported
 * MSD Supported
 * Derivation Key Index
 */

public class AccountConfigurationParameters {

    private static byte[] PPSE_AID = null;

    private static byte[] PAYWAVE_AID = null;

    private static byte[] ACP_CVM = null;

    private static byte ACP_MSDSupport = (byte) 0;

    private static byte ACP_DKI = (byte) 0;

    /**
     * Get the PPSE AID
     *
     * @return
     */
    public static byte[] getPPSEAID() {
        return PPSE_AID;
    }

    /**
     * Set the PPSE AID
     *
     * @param keyString
     */
    public static void setPPSEAID(String keyString) {
        PPSE_AID = Util.convertToBytes(keyString, "", 16);
    }

    /**
     * Get the PAYWAVE AID
     *
     * @return
     */
    public static byte[] getPAYWAVEAID() {
        return PAYWAVE_AID;
    }

    /**
     * Set the PAYWAVE AID
     *
     * @param keyString
     */
    public static void setPAYWAVEAID(String keyString) {
        PAYWAVE_AID = Util.convertToBytes(keyString, "", 16);
    }

    /**
     * Get the MSD Support Indicator
     *
     * @return
     */
    public static byte[] getCVM() {
        return ACP_CVM;
    }

    /**
     * Set the MSD Support Indicator
     *
     * @param keyString
     */
    public static void setCVM(String keyString) {
        ACP_CVM = Util.convertToBytes(keyString, "", 16);
    }

    /**
     * Get the MSD Support Indicator
     *
     * @return
     */
    public static byte getMSDSupport() {
        return ACP_MSDSupport;
    }

    /**
     * Set the MSD Support Indicator
     *
     * @param keyString
     */
    public static void setMSDSupport(String keyString) {
        ACP_MSDSupport = Util.convertToBytes(keyString, "", 16)[0];
    }

    /**
     * Get the Derivation Key Index
     *
     * @return
     */
    public static byte getDKI() {
        return ACP_DKI;
    }

    /**
     * Set the Derivation Key Index
     *
     * @param keyString
     */
    public static void setDKI(String keyString) {
        ACP_DKI = Util.convertToBytes(keyString, "", 16)[0];
    }
}
