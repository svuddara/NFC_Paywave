package nfc.visa.com.nfc.model;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.io.Serializable;

/**
 * Created by frahman on 12/14/15.
 */
public class CreatedCard implements Serializable {
    @SerializedName("token")
    @Expose
    private String token;
    @SerializedName("pan")
    @Expose
    private String pan;
    @SerializedName("expiration")
    @Expose
    private String expiration;
    @SerializedName("state")
    @Expose
    private String state;
    @SerializedName("user_token")
    @Expose
    private String userToken;
    @SerializedName("card_product_token")
    @Expose
    private String cardProductToken;
    @SerializedName("last_four")
    @Expose
    private String lastFour;
    @SerializedName("pin_is_set")
    @Expose
    private Boolean pinIsSet;
    @SerializedName("state_reason")
    @Expose
    private String stateReason;
    @SerializedName("fulfillment_status")
    @Expose
    private String fulfillmentStatus;

    /**
     * @return The token
     */
    public String getToken() {
        return token;
    }

    /**
     * @param token The token
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * @return The pan
     */
    public String getPan() {
        return pan;
    }

    /**
     * @param pan The pan
     */
    public void setPan(String pan) {
        this.pan = pan;
    }

    /**
     * @return The expiration
     */
    public String getExpiration() {
        return expiration;
    }

    /**
     * @param expiration The expiration
     */
    public void setExpiration(String expiration) {
        this.expiration = expiration;
    }

    /**
     * @return The state
     */
    public String getState() {
        return state;
    }

    /**
     * @param state The state
     */
    public void setState(String state) {
        this.state = state;
    }

    /**
     * @return The userToken
     */
    public String getUserToken() {
        return userToken;
    }

    /**
     * @param userToken The user_token
     */
    public void setUserToken(String userToken) {
        this.userToken = userToken;
    }

    /**
     * @return The cardProductToken
     */
    public String getCardProductToken() {
        return cardProductToken;
    }

    /**
     * @param cardProductToken The card_product_token
     */
    public void setCardProductToken(String cardProductToken) {
        this.cardProductToken = cardProductToken;
    }

    /**
     * @return The lastFour
     */
    public String getLastFour() {
        return lastFour;
    }

    /**
     * @param lastFour The last_four
     */
    public void setLastFour(String lastFour) {
        this.lastFour = lastFour;
    }

    /**
     * @return The pinIsSet
     */
    public Boolean getPinIsSet() {
        return pinIsSet;
    }

    /**
     * @param pinIsSet The pin_is_set
     */
    public void setPinIsSet(Boolean pinIsSet) {
        this.pinIsSet = pinIsSet;
    }

    /**
     * @return The stateReason
     */
    public String getStateReason() {
        return stateReason;
    }

    /**
     * @param stateReason The state_reason
     */
    public void setStateReason(String stateReason) {
        this.stateReason = stateReason;
    }

    /**
     * @return The fulfillmentStatus
     */
    public String getFulfillmentStatus() {
        return fulfillmentStatus;
    }

    /**
     * @param fulfillmentStatus The fulfillment_status
     */
    public void setFulfillmentStatus(String fulfillmentStatus) {
        this.fulfillmentStatus = fulfillmentStatus;
    }
}
