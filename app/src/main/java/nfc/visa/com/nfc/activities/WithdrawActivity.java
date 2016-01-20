package nfc.visa.com.nfc.activities;

import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.widget.ImageView;

import butterknife.Bind;
import butterknife.ButterKnife;
import de.greenrobot.event.EventBus;
import de.greenrobot.event.Subscribe;
import nfc.visa.com.nfc.R;
import nfc.visa.com.nfc.model.CreateCardResponse;
import nfc.visa.com.nfc.model.Event;

public class WithdrawActivity extends AppCompatActivity {

    @Bind(R.id.omc_toolbar)
    Toolbar toolbar;
    @Bind(R.id.card_pager)
    ImageView card_pager;

    CreateCardResponse cardResponse;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_withdraw);
        ButterKnife.bind(this);

        toolbar.setTitle("NFC");
        toolbar.setTitleTextAppearance(this, android.R.style.TextAppearance_DeviceDefault_Widget_ActionBar_Title);
        toolbar.setTitleTextColor(getResources().getColor(R.color.translucent_white));
        setSupportActionBar(toolbar);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        getSupportActionBar().setHomeAsUpIndicator(getDrawable(R.drawable.hamburger_icon));
    }

    @Override
    protected void onStart() {
        super.onStart();
        EventBus.getDefault().register(this);
        //DataStore.getInstance(this).getCreatedCard();
        //DataStore.getInstance(this).getBalance();
    }

    @Override
    protected void onStop() {
        super.onStop();
        EventBus.getDefault().unregister(this);
    }

    @Subscribe
    public void onEvent(Event event){
        switch (event.getName()) {
            case Event.Name.EVENT_CREATED_CARD:
                cardResponse = (CreateCardResponse) event.getData();
                setCardImage(cardResponse.getType());
                break;
//            case Event.Name.EVENT_BALANCE_DATA:
//                balanceResponse = (BalanceResponse) event.getData();
//                actual_balance.setText("$"+balanceResponse.getResults().getGpa().getLedgerBalance());
//                break;
        }
    }

    private void setCardImage(String cardType) {
        int resId=0;
        switch (cardType) {
            case "Silver":
                resId = R.drawable.silver_card;
                break;
            case "Gold":
                resId = R.drawable.gold_card_gordon;
                break;
            case "Platinum":
                resId = R.drawable.platinum_card;
                break;
        }
        card_pager.setImageDrawable(getResources().getDrawable(resId));
    }

    public void paywaveClick (View view) {
        startActivity(new Intent(this, DITapNPayActivity.class));
    }
}
