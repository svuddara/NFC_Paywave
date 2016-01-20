package nfc.visa.com.nfc.model;

public class Event {

    private String name;
    private Object data;

    public Event(String name, Object data) {
        this.name = name;
        this.data = data;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }

    public interface Name {
        String EVENT_NETWORK_ERROR = "EVENT_NETWORK_ERROR";
        String EVENT_NETWORK_CHECKIN_ERROR = "EVENT_NETWORK_CHECKIN_ERROR";
        String EVENT_CARD_PRODUCTS = "EVENT_CARD_PRODUCTS";
        String EVENT_USER_DATA = "EVENT_USER_DATA";
        String EVENT_CREATED_CARD = "EVENT_CREATED_CARD";
        String EVENT_FUNDING_SOURCE = "EVENT_FUNDING_SOURCE";
        String EVENT_TRANSACTION_DATA = "EVENT_TRANSACTION_DATA";
        String EVENT_BALANCE_DATA = "EVENT_BALANCE_DATA";
    }
}
