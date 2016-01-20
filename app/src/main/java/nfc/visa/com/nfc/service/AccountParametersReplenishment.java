package nfc.visa.com.nfc.service;

/**
 * Account Parameters Replenishment
 * Per section 6.4.3, Table 3
 * <p/>
 * Account Parameters Index
 * Sequence counter
 * Transaction log
 * - Timestamp
 * - Unpredictable Number
 * - qVSDC/MSD Transaction
 * MAC
 */

public class AccountParametersReplenishment {

    private static byte[] APR_AccountParametersIndex = null;

    private static byte APR_SequenceCounter = (byte) 0;

    private static byte[] APR_TransactionLog = null;

    private static byte[] APR_MAC = null;

    /**
     * Get the Account Parameters Index
     *
     * @return
     */
    public static byte[] getAccountParametersIndex() {
        return APR_AccountParametersIndex;
    }

    /**
     * Set the Account Parameters Index
     *
     * @param keyString
     */
    public static void setAccountParametersIndex(String keyString) {
        APR_AccountParametersIndex = Util.convertToBytes(keyString, "", 16);
    }

    /**
     * Get the Sequence Counter
     *
     * @return
     */
    public static byte getSequenceCounter() {
        return APR_SequenceCounter;
    }

    /**
     * Set the Sequence Counter
     *
     * @param keyString
     */
    public static void setSequenceCounter(String keyString) {
        APR_SequenceCounter = Util.convertToBytes(keyString, "", 16)[0];
    }

    /**
     * Get the Transaction Log
     *
     * @return
     */
    public static byte[] getTransactionLog() {
        return APR_TransactionLog;
    }

    /**
     * Set the Transaction Log
     *
     * @param keyString
     */
    public static void setTransactionLog(String keyString) {
        APR_TransactionLog = Util.convertToBytes(keyString, "", 16);
    }

    /**
     * Get the MAC
     *
     * @return
     */
    public static byte[] getMAC() {
        return APR_MAC;
    }

    /**
     * Set the MAC	 *
     *
     * @param keyString
     */
    public static void setMAC(String keyString) {
        APR_MAC = Util.convertToBytes(keyString, "", 16);
    }

}
