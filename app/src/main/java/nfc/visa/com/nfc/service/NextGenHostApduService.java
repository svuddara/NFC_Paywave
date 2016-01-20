package nfc.visa.com.nfc.service;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import java.util.Arrays;

import nfc.visa.com.nfc.activities.WithdrawActivity;

import static nfc.visa.com.nfc.service.Constants.CLA_INS_STORE_DATA;
import static nfc.visa.com.nfc.service.Constants.CLA_INS_VOP_GET_DATA;
import static nfc.visa.com.nfc.service.Constants.CLA_INS_VOP_GET_PROC_OPTS;
import static nfc.visa.com.nfc.service.Constants.CLA_INS_VOP_READ_RECORD;
import static nfc.visa.com.nfc.service.Constants.CLA_INS_VOP_SELECT;
import static nfc.visa.com.nfc.service.Constants.INDEX_ISO7816_SW_CONDITIONS_NOT_SATISFIED;
import static nfc.visa.com.nfc.service.Constants.ISO7816_SECURITY_STATUS_NOT_SATISFIED;
import static nfc.visa.com.nfc.service.Constants.ISO7816_SW_CONDITIONS_NOT_SATISFIED;
import static nfc.visa.com.nfc.service.Constants.ISO7816_SW_FILE_NOT_FOUND;
import static nfc.visa.com.nfc.service.Constants.ISO7816_SW_FUNC_NOT_SUPPORTED;
import static nfc.visa.com.nfc.service.Constants.ISO7816_SW_INS_NOT_SUPPORTED;
import static nfc.visa.com.nfc.service.Constants.ISO7816_SW_NO_ERROR;
import static nfc.visa.com.nfc.service.Constants.ISO7816_SW_WRONG_DATA;
import static nfc.visa.com.nfc.service.Constants.MAXAPDU_SIZE;
import static nfc.visa.com.nfc.service.Constants.OFFSET_CLA;
import static nfc.visa.com.nfc.service.Constants.OFFSET_P1;
import static nfc.visa.com.nfc.service.Constants.SELECT_PPSE_APDU;
import static nfc.visa.com.nfc.service.Constants.STATE_BLOCKED;
import static nfc.visa.com.nfc.service.Constants.STATE_GET_PROC_OPTS;
import static nfc.visa.com.nfc.service.Constants.STATE_READ_RECORD;
import static nfc.visa.com.nfc.service.Constants.STATE_SELECT_PAYWAVE;
import static nfc.visa.com.nfc.service.Constants.STATE_SELECT_PPSE;
import static nfc.visa.com.nfc.service.Constants.SW_HCE_INVALID_SELECT;
import static nfc.visa.com.nfc.service.VCPCSProcess.getProcessingOptions;
import static nfc.visa.com.nfc.service.VCPCSProcess.getTagValue;
import static nfc.visa.com.nfc.service.VCPCSProcess.readRecord;
import static nfc.visa.com.nfc.service.VCPCSProcess.selectPAYWAVE;
import static nfc.visa.com.nfc.service.VCPCSProcess.selectPPSE;
import static nfc.visa.com.nfc.service.VCPCSProcess.storeData;


//import com.visa.marqeta.activity.DIPaymentSentActivity;

/**
 * Created by uvashish on 8/21/15.
 */
public class NextGenHostApduService extends HostApduService {

    private static final String TAG = NextGenHostApduService.class.getSimpleName();

    public static final String TRANSACTION_COMPLETED_SUCCESSFULLY = "TRANSACTION_COMPLETED_SUCCESSFULLY";
    public static final int BROADCAST_HANDLED_TRANSACTION_COMPLETE = -111;

    static byte APDUstate = (byte) 0;
    private static byte lastCommandAPDU = (byte) 0;

    @Override
    public byte[] processCommandApdu(byte[] apduBuffer, Bundle extras) {
        String buffer_str = Arrays.toString(apduBuffer);
        Log.v(TAG, buffer_str);
        String inboundApduDescription = null;
        byte[] responseApdu = new byte[2];
        byte[] outBuffer = new byte[MAXAPDU_SIZE];
        int returnVal = 0;

        short cla_ins = Util.getShort(apduBuffer, OFFSET_CLA);
        short p1_p2 = Util.getShort(apduBuffer, OFFSET_P1);


        switch (cla_ins) {
            case CLA_INS_VOP_SELECT:
                inboundApduDescription = "Received Select Command: ";
                if (Arrays.equals(SELECT_PPSE_APDU, apduBuffer)) {
                    inboundApduDescription = "Received Select PPSE: ";
                    returnVal = selectPPSE(apduBuffer, outBuffer);
                    if (returnVal < 0) {
                        responseApdu = new byte[2];
                        Util.arrayCopy(ISO7816_SW_CONDITIONS_NOT_SATISFIED, (short) 0, responseApdu, (short) 0, (short) ISO7816_SW_CONDITIONS_NOT_SATISFIED.length);
                    } else {
                        responseApdu = new byte[returnVal];
                        Util.arrayCopy(outBuffer, (short) 0, responseApdu, (short) 0, (short) returnVal);
                        lastCommandAPDU = STATE_SELECT_PPSE;
                    }
                } else {
                    if (lastCommandAPDU == STATE_SELECT_PPSE) {
                        inboundApduDescription = "Received Select PAYWAVE: ";
                        returnVal = selectPAYWAVE(apduBuffer, outBuffer);
                        if (returnVal < 0) {
                            responseApdu = new byte[2];
                            if (returnVal == INDEX_ISO7816_SW_CONDITIONS_NOT_SATISFIED) {
                                Util.arrayCopy(ISO7816_SW_CONDITIONS_NOT_SATISFIED, (short) 0, responseApdu, (short) 0, (short) ISO7816_SW_CONDITIONS_NOT_SATISFIED.length);
                            } else {
                                //Util.arrayCopy(SW_VIS_SELECTED_FILE_INVALIDATED, (short)0, responseApdu, (short)0, (short)SW_VIS_SELECTED_FILE_INVALIDATED.length);	//0x6283
                                Util.arrayCopy(SW_HCE_INVALID_SELECT, (short) 0, responseApdu, (short) 0, (short) SW_HCE_INVALID_SELECT.length);    //0x6A88

                            }
                        } else {
                            responseApdu = new byte[returnVal];
                            Util.arrayCopy(outBuffer, (short) 0, responseApdu, (short) 0, (short) returnVal);
                            lastCommandAPDU = STATE_SELECT_PAYWAVE;
                        }
                    } else {
                        responseApdu = new byte[2];
                        Util.arrayCopy(ISO7816_SW_CONDITIONS_NOT_SATISFIED, (short) 0, responseApdu, (short) 0, (short) ISO7816_SW_CONDITIONS_NOT_SATISFIED.length);
                    }
                }
                break;

            case CLA_INS_VOP_GET_PROC_OPTS:
                inboundApduDescription = "Received GPO Command: ";
                if (APDUstate != STATE_BLOCKED) {
                    if (lastCommandAPDU == STATE_SELECT_PAYWAVE) {
                        inboundApduDescription = "Received GPO: ";
                        returnVal = getProcessingOptions(apduBuffer, outBuffer);
                        if (returnVal < 0) {
                            responseApdu = new byte[2];
                            if (returnVal == INDEX_ISO7816_SW_CONDITIONS_NOT_SATISFIED)
                                Util.arrayCopy(ISO7816_SW_CONDITIONS_NOT_SATISFIED, (short) 0, responseApdu, (short) 0, (short) ISO7816_SW_CONDITIONS_NOT_SATISFIED.length);
                            else
                                Util.arrayCopy(ISO7816_SW_FUNC_NOT_SUPPORTED, (short) 0, responseApdu, (short) 0, (short) ISO7816_SW_FUNC_NOT_SUPPORTED.length);    //0x6A81

                        } else {
                            responseApdu = new byte[returnVal];
                            Util.arrayCopy(outBuffer, (short) 0, responseApdu, (short) 0, (short) returnVal);
                            lastCommandAPDU = STATE_GET_PROC_OPTS;
                        }
                    } else {
                        //out of sequence
                        responseApdu = new byte[2];
                        Util.arrayCopy(ISO7816_SW_CONDITIONS_NOT_SATISFIED, (short) 0, responseApdu, (short) 0, (short) ISO7816_SW_CONDITIONS_NOT_SATISFIED.length); //0x6985
                    }
                } else {
                    responseApdu = new byte[2];        // Application blocked
                    Util.arrayCopy(ISO7816_SECURITY_STATUS_NOT_SATISFIED, (short) 0, responseApdu, (short) 0, (short) ISO7816_SECURITY_STATUS_NOT_SATISFIED.length);
                }

                break;

            case CLA_INS_VOP_READ_RECORD:
                inboundApduDescription = "Received READ RECORD Command: ";
                if ((lastCommandAPDU == STATE_GET_PROC_OPTS) || (lastCommandAPDU == STATE_READ_RECORD)) {
                    inboundApduDescription = "Received Read Record: ";
                    returnVal = readRecord(apduBuffer, outBuffer);
                    if (returnVal < 0) {
                        responseApdu = new byte[2];
                        //Util.arrayCopy(ISO7816_SW_RECORD_NOT_FOUND, (short)0, responseApdu, (short)0, (short)ISO7816_SW_RECORD_NOT_FOUND.length);	//0x6A83
                        Util.arrayCopy(ISO7816_SW_FILE_NOT_FOUND, (short) 0, responseApdu, (short) 0, (short) ISO7816_SW_FILE_NOT_FOUND.length);    //0x6A82
                    } else {
                        responseApdu = new byte[returnVal];
                        Util.arrayCopy(outBuffer, (short) 0, responseApdu, (short) 0, (short) returnVal);
                        lastCommandAPDU = STATE_READ_RECORD;
                    }
                } else {
                    responseApdu = new byte[2];
                    Util.arrayCopy(ISO7816_SW_CONDITIONS_NOT_SATISFIED, (short) 0, responseApdu, (short) 0, (short) ISO7816_SW_CONDITIONS_NOT_SATISFIED.length);
                }

                break;

            case CLA_INS_STORE_DATA:
                inboundApduDescription = "Received STORE DATA Command: ";
                //this is for QA or debugging only
                if (lastCommandAPDU == STATE_SELECT_PAYWAVE) {
                    inboundApduDescription = "Received Store Data: ";
                    responseApdu = storeData(apduBuffer, (short) 0, (short) apduBuffer.length);
                } else {
                    responseApdu = new byte[2];
                    Util.arrayCopy(ISO7816_SW_CONDITIONS_NOT_SATISFIED, (short) 0, responseApdu, (short) 0, (short) ISO7816_SW_CONDITIONS_NOT_SATISFIED.length);
                }

                break;

            case CLA_INS_VOP_GET_DATA:
                inboundApduDescription = "Received GET DATA Command: ";
                //this is for QA or debugging only
                if (lastCommandAPDU == STATE_SELECT_PAYWAVE) {
                    inboundApduDescription = "Received Get data: ";
                    returnVal = getTagValue(p1_p2, outBuffer);
                    if (returnVal < 0) {
                        responseApdu = new byte[2];
                        Util.arrayCopy(ISO7816_SW_WRONG_DATA, (short) 0, responseApdu, (short) 0, (short) ISO7816_SW_WRONG_DATA.length);
                    } else {
                        responseApdu = new byte[returnVal + 2];
                        Util.arrayCopy(outBuffer, (short) 0, responseApdu, (short) 0, (short) returnVal);
                        Util.arrayCopy(ISO7816_SW_NO_ERROR, (short) 0, responseApdu, (short) returnVal, (short) ISO7816_SW_NO_ERROR.length);
                    }
                    //ByteBuffer.allocate(15);
                } else {
                    responseApdu = new byte[2];
                    Util.arrayCopy(ISO7816_SW_CONDITIONS_NOT_SATISFIED, (short) 0, responseApdu, (short) 0, (short) ISO7816_SW_CONDITIONS_NOT_SATISFIED.length);
                }

                break;


            default:
                inboundApduDescription = "Received Unhandled APDU: ";
                responseApdu = new byte[2];
                Util.arrayCopy(ISO7816_SW_INS_NOT_SUPPORTED, (short) 0, responseApdu, (short) 0, (short) ISO7816_SW_INS_NOT_SUPPORTED.length);    //0x6D00
        }


        if (responseApdu != null) {
            //DebugActivity.sendLog(TAG, inboundApduDescription, Util.byteArrayToHex(apduBuffer),
            //        " / Response: ", Util.byteArrayToHex(responseApdu));
        }


               /*
        public final void sendResponseApdu (byte[] responseApdu)

        Added in API level 19
        Sends a response APDU back to the remote device.

        Note: this method may be called from any thread and will not block.

        Parameters
        responseApdu	A byte-array containing the reponse APDU.
	   */

        Log.v(TAG, "inboundApduDescription " + inboundApduDescription);

        String response_str = Arrays.toString(responseApdu);
        Log.v(TAG, "Response");
        Log.v(TAG, response_str);
        return responseApdu;

    }

    @Override
    public void onDeactivated(int reason) {
        //DebugActivity.sendLog(TAG, "onDeactivated(", String.valueOf(reason), ")");
        Log.d(TAG, "onDeactivated(" + String.valueOf(reason) + ")");

        //todo atomic operation
        //byte[] responseApdu = ISO7816_SW_CONDITIONS_NOT_SATISFIED;
        //sendResponseApdu(byte[] responseApdu);	//Sends a response APDU back to the remote device.
        if (reason == DEACTIVATION_DESELECTED) //0x00000001
        {
            //Indicates deactivation was due to a different AID being selected
            //(which implicitly deselects the AID currently active on the logical channel).
            //Note that this next AID may still be resolved to this service,
            //in which case processCommandApdu(byte[], Bundle) will be called again.
            //DebugActivity.sendLog("onDeactivated", "DEACTIVATION_DESELECTED");
            Log.d(TAG, "onDeactivated: DEACTIVATION_DESELECTED");
        } else if (reason == DEACTIVATION_LINK_LOSS) //0x00000000
        {
            //Indicates deactivation was due to the NFC link being lost.
            //DebugActivity.sendLog("onDeactivated", "DEACTIVATION_LINK_LOSS");
            Log.d(TAG, "onDeactivated: DEACTIVATION_LINK_LOSS");
        }

        Intent intent = new Intent(TRANSACTION_COMPLETED_SUCCESSFULLY);
        sendOrderedBroadcast(intent, null, new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                int result = getResultCode();
                if(result != BROADCAST_HANDLED_TRANSACTION_COMPLETE){
                    showTransactionCompleteNotification();
                }
            }
        }, null, Activity.RESULT_OK, null, null);
    }

    private void showTransactionCompleteNotification(){
        Intent intent1 = new Intent(getApplicationContext(), WithdrawActivity.class);
        intent1.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        getApplicationContext().startActivity(intent1);
    }
}