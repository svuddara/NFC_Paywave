package nfc.visa.com.nfc.service;

/**
 * Created by uvashish on 8/24/15.
 */
public class TLV implements Constants {

    //DGI 9102
    protected static byte[] Tag_PPSE_DF = null;                        // Tag 84, PPSE AID
    protected static byte[] Tag_PPSE_AppLabel = null;                // Tag 50, Application Label
    protected static byte[] Tag_PPSE_AppPriorityIndicator = null;    // Tag 87, Application Priority Indicator
    protected static byte[] Tag_Kernel_Identifier = null;            // Tag 9F2A, Kernel Identifier

    //DGI 9103
    protected static byte[] Tag_PAYWAVE_DF = null;                    // Tag 84, PAYWAVE DF
    protected static byte[] Tag_Aid = null;                            // Tag 4F, PAYWAVE AID
    protected static byte[] Tag_AppLabel = null;                    // Tag 50, Application Label
    protected static byte[] Tag_PDOL = null;                        // Tag 9F38, PDOL

    //DGI 9115
    //protected static byte[] Tag_QVSDC_AIP = null;					// Tag 82, AIP
    //protected static byte[] Tag_QVSDC_AFL = null;					// Tag 94, AFL
    protected static byte[] Tag_QVSDC_T2ED = null;                    // Tag 57, Track 2 Equivalent Data
    protected static byte[] Tag_QVSDC_PSN = null;                    // Tag 5F34, Application PAN Sequence Number
    protected static byte[] Tag_QVSDC_IAD = null;                    // Tag 9F10, Issuer Application Data
    protected static byte[] Tag_QVSDC_AC = null;                    // Tag 9F26, Application Cryptogram
    protected static byte[] Tag_QVSDC_CID = null;                    // Tag 9F27, Cryptogram Information Data
    //protected static byte[] Tag_QVSDC_ATC = null;					// Tag 9F36, Application Transaction Counter
    protected static byte[] Tag_QVSDC_SDAD = null;                    // Tag 9F4B, Signed Dynamic Application Data
    protected static byte[] Tag_QVSDC_CTQ = null;                    // Tag 9F6C, Card Transaction Qualifiers
    protected static byte[] Tag_QVSDC_FFI = null;                    // Tag 9F6E, Form Factor Indicator

    protected static byte[] Tag_QVSDC_9F10_LEN = null;                // part of tag '9F10' length of 9F10
    protected static byte[] Tag_QVSDC_IAD_LEN = null;                // part of tag '9F10' length of IAD
    protected static byte[] Tag_QVSDC_CVN = null;                    // part of tag '9F10' Card Verification Number
    protected static byte[] Tag_QVSDC_DKI = null;                    // part of tag '9F10' Derived Key Indicator
    protected static byte[] Tag_QVSDC_CVR = null;                    // part of tag '9F10' Card Verification Result
    protected static byte[] Tag_QVSDC_DWPI = null;                    // part of tag '9F10' Digital Wallet Provider ID
    protected static byte[] Tag_QVSDC_DDLUK = null;                    // part of tag '9F10' Derivation Data for LUK
    protected static byte[] Tag_QVSDC_IDD_FORMAT = null;            // part of tag '9F10' IDD format
    protected static byte[] Tag_QVSDC_IDD_PADDING = null;            // part of tag '9F10' IDD padding zeroes

    //DGI9206
    //protected static byte[] Tag_MSD_AIP = null;						// Tag 82, AIP
    //protected static byte[] Tag_MSD_AFL = null;						// Tag 94, AFL

    //DGI 0303
    protected static byte[] Tag_QVSDC_AUC = null;                    // Tag 9F07, Application Usage Control
    protected static byte[] Tag_QVSDC_CardholderName = null;        // Tag 5F20, Cardholder Name
    protected static byte[] Tag_QVSDC_CED = null;                    // Tag 9F7C, Consumer Exclusive Data
    protected static byte[] Tag_QVSDC_TRID = null;                    // Tag 9F19, Token Requester ID

    //DGI 0101
    protected static byte[] Tag_MSD_T2ED = null;                    // Tag 57, Track 2 Equivalent Data
    protected static byte[] Tag_MSD_CardholderName = null;            // Tag 5F20, Cardholder Name

    //DGI 3001
    protected static byte[] Tag_CAP = null;                            // tag '9F68, Card Additional Processes - 4 bytes


    protected static byte[] Tag_ACCOUNT_PARAMETERS_LUK = null;        // Account Parameters Limited Use Key
    protected static byte[] Tag_ACCOUNT_PARAMETERS_INDEX = null;    // Account Parameters Index YHHHHCC


}