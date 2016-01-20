package nfc.visa.com.nfc.model;

import android.support.annotation.Nullable;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.io.Serializable;

/**
 * Created by frahman on 12/14/15.
 */
public class CreateCardResponse implements Serializable {

    @SerializedName("success")
    @Expose
    private Boolean success;
    @SerializedName("card_token")
    @Expose
    private String cardToken;
    @Nullable
    @SerializedName("card_type")
    @Expose
    private String type;
    @SerializedName("_results")
    @Expose
    private CreatedCard createdCard;

    /**
     * @return The success
     */
    public Boolean getSuccess() {
        return success;
    }

    /**
     * @param success The success
     */
    public void setSuccess(Boolean success) {
        this.success = success;
    }

    /**
     * @return The cardToken
     */
    public String getCardToken() {
        return cardToken;
    }

    /**
     * @param cardToken The card_token
     */
    public void setCardToken(String cardToken) {
        this.cardToken = cardToken;
    }

    /**
     * @return createdCard
     */
    public CreatedCard getCreatedCard() {
        return createdCard;
    }

    /**
     * @param createdCard
     */
    public void setCreatedCard(CreatedCard createdCard) {
        this.createdCard = createdCard;
    }

    @Nullable
    public String getType() {
        return type;
    }

    public void setType(@Nullable String type) {
        this.type = type;
    }
}
