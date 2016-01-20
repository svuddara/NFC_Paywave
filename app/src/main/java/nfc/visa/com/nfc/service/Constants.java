package nfc.visa.com.nfc.service;

import java.util.regex.Pattern;

/**
 * Created by uvashish on 8/24/15.
 */
public interface Constants {

    //tag '9F7D' � Application Code Level
    final static byte[] TAG_ACL = {(byte) 0x31, (byte) 0x32,            // day
            (byte) 0x30, (byte) 0x37,                                    // month
            (byte) 0x31, (byte) 0x34,                                    // year
            (byte) 0x20,
            'V', 'C', 'P', 'C', 'S',                                    // VCPCS
            (byte) 0x20,
            (byte) 0x31, (byte) 0x2E, (byte) 0x33, (byte) 0x2E, (byte) 0x30};    // 1.3.0
    //ACL=DDMMYY VCPCS 1.3.0

    // Transaction Counter
    final static int MAX_ATC = 0xFFFF;        //65535
    final static short MAXAPDU_SIZE = (short) 256;

    // Supported Commands  (Used in the "process()" and/or "processData()" methods).
    final static short CLA_INS_VOP_SELECT = (short) 0x00A4;
    final static short CLA_INS_VOP_GET_PROC_OPTS = (short) 0x80A8;
    final static short CLA_INS_VOP_READ_RECORD = (short) 0x00B2;
    final static short CLA_INS_STORE_DATA = (short) 0x80E2;
    final static short CLA_INS_VOP_GET_DATA = (short) 0x80CA;
    final static short CLA_INS_VOP_PUT_DATA_SCRIPT = (short) 0x04DA;

    final static byte[] CRYPTO_MSD = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01};
    final static byte[] CRYPTO_IV = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    final static short CRYPTO_KEY_LENGTH = (short) 24;

    static final byte[] SELECT_PPSE_APDU = {
            (byte) 0x00, // CLA (class of command)
            (byte) 0xA4, // INS (instruction); A4 = select
            (byte) 0x04, // P1  (parameter 1)  (0x04: select by name)
            (byte) 0x00, // P2  (parameter 2)
            (byte) 0x0E, // LC  (length of data)  14 (0x0E) = length("2PAY.SYS.DDF01")
            // 2PAY.SYS.DDF01 (ASCII values of characters used):
            // This value requests the card or payment device to list the application
            // identifiers (AIDs) it supports in the response:
            '2', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1',
            (byte) 0x00 // LE   (max length of expected result, 0 implies 256)
    };

    final static byte[] ISO7816_SW_NO_ERROR = {(byte) 0x90, (byte) 0x00};
    final static byte[] ISO7816_SW_WRONG_LENGTH = {(byte) 0x67, (byte) 0x00};
    final static byte[] ISO7816_SECURITY_STATUS_NOT_SATISFIED = {(byte) 0x69, (byte) 0x82};
    final static byte[] ISO7816_SW_CONDITIONS_NOT_SATISFIED = {(byte) 0x69, (byte) 0x85};
    final static byte[] ISO7816_SW_COMMAND_NOT_ALLOWED = {(byte) 0x69, (byte) 0x86};
    final static byte[] ISO7816_SW_DATA_INVALID = {(byte) 0x69, (byte) 0x84};
    final static byte[] ISO7816_SW_WRONG_DATA = {(byte) 0x6A, (byte) 0x80};
    final static byte[] ISO7816_SW_FUNC_NOT_SUPPORTED = {(byte) 0x6A, (byte) 0x81};
    final static byte[] ISO7816_SW_RECORD_NOT_FOUND = {(byte) 0x6A, (byte) 0x83};
    final static byte[] ISO7816_SW_INCORRECT_P1P2 = {(byte) 0x6A, (byte) 0x86};
    final static byte[] ISO7816_SW_INS_NOT_SUPPORTED = {(byte) 0x6D, (byte) 0x00};
    final static byte[] ISO7816_SW_CLA_NOT_SUPPORTED = {(byte) 0x6E, (byte) 0x00};
    final static byte[] ISO7816_UNKNOWN_ERROR_RESPONSE = {(byte) 0x6F, (byte) 0x00};
    final static byte[] ISO7816_SW_FILE_NOT_FOUND = {(byte) 0x6A, (byte) 0x82};


    //final static Object[] ISO7816 =   new Object[100];
    //ISO7816 =  new byte[MAXAPDU_SIZE];
    //{(byte)0x90, (byte)0x00};

    final static int INDEX_ISO7816_SW_NO_ERROR = 0;
    final static int INDEX_ISO7816_SW_WRONG_LENGTH = -1;
    final static int INDEX_ISO7816_SECURITY_STATUS_NOT_SATISFIED = -2;
    final static int INDEX_ISO7816_SW_CONDITIONS_NOT_SATISFIED = -3;
    final static int INDEX_ISO7816_SW_COMMAND_NOT_ALLOWED = -4;
    final static int INDEX_ISO7816_SW_DATA_INVALID = -5;
    final static int INDEX_ISO7816_SW_WRONG_DATA = -6;
    final static int INDEX_ISO7816_SW_FUNC_NOT_SUPPORTED = -7;
    final static int INDEX_ISO7816_SW_RECORD_NOT_FOUND = -8;
    final static int INDEX_ISO7816_SW_INCORRECT_P1P2 = -9;
    final static int INDEX_ISO7816_SW_INS_NOT_SUPPORTED = -10;
    final static int INDEX_ISO7816_SW_CLA_NOT_SUPPORTED = -11;
    final static int INDEX_ISO7816_UNKNOWN_ERROR_RESPONSE = -12;
    final static int INDEX_SW_CPS_UNKNOWN_DGI = -13;
    final static int INDEX_SW_VIS_SELECTED_FILE_INVALIDATED = -14;
    final static int INDEX_SW_HCE_INVALID_SELECT = -15;
    final static int INDEX_ISO7816_SW_FILE_NOT_FOUND = -16;

    // Non-ISO7816 Error Codes
    final static byte[] SW_VIS_AUTHENTICATION_FAILED = {(byte) 0x63, (byte) 0x00};
    final static byte[] SW_VIS_SM_MISSING = {(byte) 0x69, (byte) 0x87};
    final static byte[] SW_VIS_SM_INCORRECT = {(byte) 0x69, (byte) 0x88};
    final static byte[] SW_VIS_SELECTED_FILE_INVALIDATED = {(byte) 0x62, (byte) 0x83};
    final static byte[] SW_CPS_UNKNOWN_DGI = {(byte) 0x6A, (byte) 0x88};
    final static byte[] SW_HCE_INVALID_SELECT = {(byte) 0x6A, (byte) 0x88};


    final static byte FCI_TEMPLATE = (byte) 0x6F;
    final static byte FCI_PPROPRIETARY_TEMPLATE = (byte) 0xA5;
    final static byte DIRECTORY_ENTRY = (byte) 0x61;
    final static byte RESP_MSG_TEMPLATE_FORMAT_1 = (byte) 0x80;
    final static byte RESP_MSG_TEMPLATE_FORMAT_2 = (byte) 0x77;
    final static byte[] FCI_ISSUER_DISCRETIONARY_DATA = {(byte) 0xBF, (byte) 0x0C};

    static final Pattern TRACK_2_PATTERN = Pattern.compile(".*;(\\d{12,19}=\\d{1,128})\\?.*");

    static final byte OFFSET_CLA = 0;
    static final byte OFFSET_INS = 1;
    static final byte OFFSET_P1 = 2;
    static final byte OFFSET_P2 = 3;
    static final byte OFFSET_LC = 4;
    static final byte OFFSET_CDATA = 5;
    static final short STOREDATA_DATA_OFFSET = (short) (OFFSET_CDATA + 3);
    static final byte TTQ_INDEX = OFFSET_CDATA + 2; //first byte of data will be TTQ byte 1
    static final byte TTQ_MASK = (byte) 0xA0;    //1010 0000
    static final byte MSD_TTQ = (byte) 0x80;        //1000 0000
    static final byte QVSDC_TTQ = (byte) 0x20;    //0010 0000
    static final byte STATE_DEACTIVATED = 0x00;
    static final byte STATE_SELECT_PPSE = 0x01;
    static final byte STATE_SELECT_PAYWAVE = 0x02;
    static final byte STATE_GET_PROC_OPTS = 0x03;
    static final byte STATE_READ_RECORD = 0x04;
    static final byte STATE_STORE_DATA = 0x05;
    static final byte STATE_ERROR = 0x5F;
    static final byte STATE_BLOCKED = 0x7F;


    // Our Complex Boolean Values
    final static byte OURTRUE = (byte) 0x5A;
    final static byte OURFALSE = (byte) 0xA5;
    final static byte FAILURE = (byte) 0xA5;

    final static byte FILE_SYSTEM_DIR_SIZE = (byte) 32;
    final static short LOG_FILE_SIZE = (short) 41;
    final static byte LOGFILE_SFI = (byte) 0;
    final static byte LOGFILE_RECS = (byte) 1;

    final static byte MYTL_Length = (byte) 2;

    // HCE Profiles used for AIP and AFL arrays.
    final static byte PROFILE_NONE = (byte) -1;
    final static byte PROFILE_MSD = (byte) 0;
    final static byte PROFILE_QVSDC_ONLINE_WO_ODA = (byte) 1;
    final static byte PROFILE_QVSDC_ONLINE_WITH_ODA = (byte) 2;
    final static byte NUM_OF_PROFILES = (byte) 3;

    final static byte DCRYPTO_TRACK2_SFI = (byte) 0;  // 1 byte from the AFL List.
    final static byte DCRYPTO_TRACK2_REC = (byte) 1;  // 1 byte from the AFL List.
    final static byte DCRYPTO_TRACK2_OFF = (byte) 2;  // 1 byte; offset into the record
    final static byte DCRYPTO_DATASIZE = (byte) 3;  // The size of the byte array.

    //DGI 9102 Select PPSE response
    final static short PPSE_FCI_TEMPLATE_OFFSET = (short) 8;
    final static short PPSE_DF_NAME_OFFSET = (short) 10;    //0x0A
    final static short PPSE_FCI_PROPRIETARY_TEMPLATE_OFFSET = (short) 26;    //0x1A
    final static short PPSE_DIRECTORY_ENTRY_OFFSET = (short) 31;    //0x1F

    //Visa PIXs:
    //	'1010' � Visa Debit and Visa Credit
    //	'2010' � Visa Electron
    //	'3010' � Interlink
    //	'8010' � PLUS
    final static short VISAAID_DEBITCREDIT = (short) 0;
    final static short VISAAID_ELECTRON = (short) 1;
    final static short VISAAID_INTERLINK = (short) 2;
    final static short VISAAID_PLUS = (short) 3;
    final static short VISAAID_SIZE = (short) 4;

    //DGI 9102 Select PAYWAVE response
    final static short PAYWAVE_FCI_TEMPLATE_OFFSET = (short) 8;
    final static short PAYWAVE_DF_NAME_OFFSET = (short) 10;    //0x0A
    final static short PAYWAVE_FCI_PROPRIETARY_TEMPLATE_OFFSET = (short) 19;    //0x13


    // AIP bits
    // DATA DICTIONARY: AIP, primitive tag '82'
    final static short AIP_SDA_SUPP = (short) 0x4000;
    final static short AIP_DDA_SUPP = (short) 0x2000;

    //DATA DICTIONARY: Card Additional Processes, primitive tag '9F68' - 4 bytes
    final static byte CAP_BYTE_1 = (byte) 0;
    final static byte CAP_BYTE_2 = (byte) 1;
    final static byte CAP_BYTE_3 = (byte) 2;
    final static byte CAP_BYTE_4 = (byte) 3;
    final static byte CAP_SIZE = (byte) 4;

    final static byte CAP_B1b8_LOW_VALUE_CHECK = (byte) 0x80;
    final static byte CAP_B1b7_LV_AND_CTTA_CHECK = (byte) 0x40;
    final static byte CAP_B1b6_COUNT_QVSDC_ONLINE_TXN = (byte) 0x20;
    final static byte CAP_B1b5_STREAMLINED_QVSDC_SUPPORTED = (byte) 0x10;
    final static byte CAP_B1b4_PIN_TRYS_EXCEEDED_CHECK = (byte) 0x08;
    final static byte CAP_B1b3_OFFLINE_INTL_TXN_ALLOWED = (byte) 0x04;
    final static byte CAP_B1b2_CARD_PREFERS_CONTACT_VSDC_FOR_ONLINE = (byte) 0x02;
    final static byte CAP_B1b1_RETURN_AVAILABLE_OFFLINE_SPENDING_AMOUNT = (byte) 0x01;

    final static byte CAP_B2b8_INCLUDE_CNTRY_CD_IN_DETERMINE_INTL_TXN = (byte) 0x80;
    final static byte CAP_B2b7_INTL_TXN_NOT_ALLOWED = (byte) 0x40;
    final static byte CAP_B2b6_DISABLE_ODA_AUTHORIZATIONS = (byte) 0x20;
    final static byte CAP_B2b5_ISSUER_UPDATE_PROCESSING_SUPPORTED = (byte) 0x10;
    final static byte CAP_B2b3_QVSDC_OFFLINE_ONLY = (byte) 0x04;        //prepaid vcps

    final static byte CAP_B3b8_ONLINE_PIN_SUPPORTED_FOR_DOMESITC_TXN = (byte) 0x80;
    final static byte CAP_B3b7_ONLINE_PIN_SUPPORTED_FOR_INTL_TXN = (byte) 0x40;
    final static byte CAP_B3b6_CONTACT_CHIP_OFFLINE_PIN_SUPPORTED = (byte) 0x20;
    final static byte CAP_B3b5_SIGNATURE_SUPPORTED = (byte) 0x10;
    final static byte CAP_B3b4_CONSUMER_DEVICE_CVM_SUPPORTED = (byte) 0x08;


    //DATA DICTIONARY: CVR, part of primitive tag '9F10' - 6 bytes
    //CVM Verifying Entity
    final static byte CVR_B1b85_0000_NO_CD_CVM = (byte) 0x00;  // 0000 0000
    final static byte CVR_B1b85_0001_VMPA = (byte) 0x10;  // 0001 0000
    final static byte CVR_B1b85_0010_MG = (byte) 0x20;  // 0010 0000
    final static byte CVR_B1b85_0011_CO_RESIDE_SE = (byte) 0x30;  // 0011 0000
    final static byte CVR_B1b85_0100_TEE = (byte) 0x40;  // 0100 0000
    final static byte CVR_B1b85_0101_MOBILE_APP = (byte) 0x50;  // 0101 0000
    final static byte CVR_B1b85_0110_TERMINAL = (byte) 0x60;  // 0110 0000
    final static byte CVR_B1b85_0111_VERIFIED_CLOUD = (byte) 0x70;  // 0111 0000
    final static byte CVR_B1b85_1000_VERIFIED_MOBILE_DEVICE = (byte) 0x80;  // 1000 0000
    //CVM Verified Type
    final static byte CVR_B1b41_0000_NO_CD_CVM = (byte) 0x00;  // 0000 0000
    final static byte CVR_B1b41_0001_PASSCODE = (byte) 0x01;  // 0000 0001
    final static byte CVR_B1b41_0010_OTHER_CD_CVM = (byte) 0x02;  // 0000 0010
    final static byte CVR_B1b41_0011_MOBILE_DEVICE = (byte) 0x03;  // 0000 0011
    final static byte CVR_B1b41_1101_SIGNATURE = (byte) 0x0D;  // 0000 1101
    final static byte CVR_B1b41_1110_ONLINE_PIN = (byte) 0x0E;  // 0000 1110


    final static byte CVR_B2b8765_1111_APP_DISABLED = (byte) 0xF0;  // 1111 0000
    final static byte CVR_B2b87_CLEAR_BITS = (byte) 0x3F;  // 0011 1111; used to clear 8 and 7
    final static byte CVR_B2b87_00_AAC2 = (byte) 0x00;  // 0000 0000
    final static byte CVR_B2b87_01_TC2 = (byte) 0x40;  // 0100 0000
    final static byte CVR_B2b87_10_NO2 = (byte) 0x80;  // 1000 0000
    final static byte CVR_B2b87_11_RFU = (byte) 0xC0;  // 1100 0000

    final static byte CVR_B2b65_CLEAR_BITS = (byte) 0xCF;  // 1100 1111; used to clear 6 and 5
    final static byte CVR_B2b65_00_AAC1 = (byte) 0x00;  // 0000 0000
    final static byte CVR_B2b65_01_TC1 = (byte) 0x10;  // 0001 0000
    final static byte CVR_B2b65_10_ARQC1 = (byte) 0x20;  // 0010 0000
    final static byte CVR_B2b65_11_RFU = (byte) 0x30;  // 0011 0000

    final static byte CVR_B2b4_ISS_AUTHENT_PERF_AND_FAILED = (byte) 0x08;
    final static byte CVR_B2b3_OFFLINE_PIN_VERIF_PERFORMED = (byte) 0x04;
    final static byte CVR_B2b2_OFFLINE_PIN_VERIF_FAILED = (byte) 0x02;
    final static byte CVR_B2b1_UNABLE_TO_GO_ONLINE = (byte) 0x01;

    final static byte CVR_B3b8_LAST_ONLINE_TRANS_NOT_COMPLTD = (byte) 0x80;
    final static byte CVR_B3b7_PIN_TRY_LIMIT_EXCDD = (byte) 0x40;
    final static byte CVR_B3b6_VELOC_EXCDD = (byte) 0x20;
    final static byte CVR_B3b5_NEW_CARD = (byte) 0x10;
    final static byte CVR_B3b4_ISS_AUTHENT_FAIL_ON_LAST_ONLINE = (byte) 0x08;
    final static byte CVR_B3b3_ISS_AUTH_NOT_DONE_AFTER_ONLINE_AUTH = (byte) 0x04;
    final static byte CVR_B3b2_APP_BLKD_PIN_LIMIT_EXCDD = (byte) 0x02;
    final static byte CVR_B3b1_SDA_FAIL = (byte) 0x01;

    final static byte CVR_B4b4_ISS_SCRIPT_FAILED_LAST_TRANS = (byte) 0x08;
    final static byte CVR_B4b3_DDA_FAIL = (byte) 0x04;
    final static byte CVR_B4b2_DDA_PERFORMED = (byte) 0x02;
    final static byte CVR_B4b1_VERIF_NOT_RCVD_FOR_PIN_EXPTING_CARD = (byte) 0x01;            //UoC

    final static short CVRLEN = 6;
    //private static byte[] CVR;  								// will be transient byte array of 4
    final static short CVR_BYTE_1 = (short) 0;
    final static short CVR_BYTE_2 = (short) 1;
    final static short CVR_BYTE_3 = (short) 2;
    final static short CVR_BYTE_4 = (short) 3;
    final static short CVR_BYTE_5 = (short) 4;
    final static short CVR_BYTE_6 = (short) 5;

    //DATA DICTIONARY: Terminal Transaction Qualifiers, primitive tag '9F66' - 4 bytes
    final static byte TTQ_B1b8_CONTACTLESS_MSD_SUPPORTED = (byte) 0x80;
    final static byte TTQ_B1b6_CONTACTLESS_QVSDC_SUPPORTED = (byte) 0x20;
    final static byte TTQ_B1b5_CONTACT_VSDC_SUPPORTED = (byte) 0x10;
    final static byte TTQ_B1b4_READER_IS_OFFLINE_ONLY = (byte) 0x08;
    final static byte TTQ_B1b3_ONLINE_PIN_SUPPORTED = (byte) 0x04;
    final static byte TTQ_B1b2_SIGNATURE_SUPPORTED = (byte) 0x02;
    final static byte TTQ_B1b1_ODA_FOR_ONLINE_AUTH_SUPPORTED = (byte) 0x01;
    final static byte TTQ_B2b8_ONLINE_CRYPTOGRAM_REQUIRED = (byte) 0x80;
    final static byte TTQ_B2b7_CVM_REQUIRED = (byte) 0x40;
    final static byte TTQ_B2b6_OFFLINE_PIN_SUPPORTED = (byte) 0x20;
    final static byte TTQ_B3b8_ISSUER_UPDATE_PROCESSING_SUPPORTED = (byte) 0x80;
    final static byte TTQ_B3b7_MOBILE_FUNC_SUPPORTED_CONSUMER_DEVICE_CVM = (byte) 0x40;


    // DATA DICTIONARY: Card Transaction Qualifiers, primitive tag '9F6C' - 2 bytes
    final static byte CTQ_BYTE_1 = (byte) 0;
    final static byte CTQ_BYTE_2 = (byte) 1;
    final static byte CTQ_SIZE = (byte) 2;

    final static byte CTQ_B1b8_ONLINE_PIN_REQUIRED = (byte) 0x80;
    final static byte CTQ_B1b7_SIGNATURE_REQUIRED = (byte) 0x40;
    final static byte CTQ_B1b6_GO_ONLINE = (byte) 0x20;
    final static byte CTQ_B1b5_TERMINATE = (byte) 0x10;
    final static byte CTQ_B1b4_RFU = (byte) 0x08;
    final static byte CTQ_B1b3_RFU = (byte) 0x04;
    final static byte CTQ_B1b2_RFU = (byte) 0x02;
    final static byte CTQ_B1b1_RFU = (byte) 0x01;
    final static byte CTQ_B2b8_CONSUMER_DEVICE_CVM_PERFORMED = (byte) 0x80;
    final static byte CTQ_B2b7_CARD_SUPPORTS_TWO_TAP = (byte) 0x40;
    final static byte CTQ_B2b6_RFU = (byte) 0x20;
    final static byte CTQ_B2b5_RFU = (byte) 0x10;
    final static byte CTQ_B2b4_RFU = (byte) 0x08;
    final static byte CTQ_B2b3_RFU = (byte) 0x04;
    final static byte CTQ_B2b2_RFU = (byte) 0x02;
    final static byte CTQ_B2b1_RFU = (byte) 0x01;
    final static byte CTQ_CLEAR_1MSBITS = (byte) 0x7F;    //0111 1111
    final static byte CTQ_CLEAR_2MSBITS = (byte) 0x3F;    //0011 1111

    final static short BCDLEN = (short) 12;

    // BCD Math Errors
    /**
     * Returned for an overflow condition.
     *
     * @see #addBCD(byte[] a, byte[] b, byte[] res)
     */
    public final static boolean OVERFLOW = false;
    /**
     * Returned for an underflow condition.
     *
     * @see #addBCD(byte[] a, byte[] b, byte[] res)
     */
    public final static boolean UNDERFLOW = false;
    /**
     * Returned when the operation was successful.
     *
     * @see #addBCD(byte[] a, byte[] b, byte[] res)
     */
    public final static boolean SUCCESS = true;
}

