package nfc.visa.com.nfc.activities;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.drawable.AnimationDrawable;
import android.graphics.drawable.Drawable;
import android.media.AudioManager;
import android.media.SoundPool;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.AlphaAnimation;
import android.view.animation.Animation;
import android.view.animation.AnimationSet;
import android.view.animation.AnimationUtils;
import android.view.animation.RotateAnimation;
import android.view.animation.ScaleAnimation;
import android.view.animation.TranslateAnimation;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;


import de.greenrobot.event.EventBus;
import de.greenrobot.event.Subscribe;
import nfc.visa.com.nfc.R;
import nfc.visa.com.nfc.model.CreateCardResponse;
import nfc.visa.com.nfc.model.Event;
import nfc.visa.com.nfc.receiver.DITransactionReceiver;
import nfc.visa.com.nfc.service.NextGenHostApduService;
import nfc.visa.com.nfc.util.DIReverseInterpolator;

public class DITapNPayActivity extends Activity {
    private Boolean soundIsReady = false;
    private float volume = 0.0f;
    private SoundPool soundPool;
    private int soundPaymentDone;
    private ImageView cardArt, chevronView, nfcLogo;
    private TextView statusView;
    private DITransactionReceiver transactionBroadcastReceiver;
    private View rootView;
    private AnimationSet cardArtIntroAnimationSet = null;
    private CreateCardResponse cardResponse;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        getWindow().setWindowAnimations(R.anim.transition_flash_in);
        super.onCreate(savedInstanceState);
        overridePendingTransition(R.anim.transition_flash_in, R.anim.transition_flash_out);
        setContentView(R.layout.activity_tapnpay);
        loadAndPrepareSoundEffect();
        rootView = findViewById(R.id.rlTapNPay);
        cardArt = (ImageView) findViewById(R.id.cardArt);
        chevronView = (ImageView) findViewById(R.id.chevron);
        nfcLogo = (ImageView) findViewById(R.id.nfcLogo);
        statusView = (TextView) findViewById(R.id.tvHelperTxt);

        nfcLogo.setVisibility(View.INVISIBLE);
        statusView.setVisibility(View.INVISIBLE);
        chevronView.setVisibility(View.INVISIBLE);

        nfcLogo.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleArrowAnimation(true);
            }
        });


        if(transactionBroadcastReceiver == null) {
            transactionBroadcastReceiver = new DITransactionReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    setResultCode(NextGenHostApduService.BROADCAST_HANDLED_TRANSACTION_COMPLETE);
                    toggleArrowAnimation(true);
                }
            };
        }
        registerReceiver(transactionBroadcastReceiver, new IntentFilter(NextGenHostApduService.TRANSACTION_COMPLETED_SUCCESSFULLY));
    }

    @Override
    protected void onStart() {
        super.onStart();
        EventBus.getDefault().register(this);
        //DataStore.getInstance(this).getCreatedCard();
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
        cardArt.setImageDrawable(getResources().getDrawable(resId));
    }
    @Override
    public void onBackPressed() {
        super.onBackPressed();
        cancelPayment();
        overridePendingTransition(R.anim.transition_flash_in, R.anim.transition_flash_out);
    }

    @Override
    public void onDestroy() {
        recycleMemoryForAnimation();
        unRegisterTransactionReceiver();
        super.onDestroy();
    }
    @Override
    public void onWindowFocusChanged (boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if(this.cardArtIntroAnimationSet != null){
            return;
        }
        int width = rootView.getWidth();
        if(width == 0){
            return;
        }
        int chevron_w = chevronView.getWidth();
        int chevron_h = (int)((float)chevron_w /228.0 * 363.0);

        android.view.ViewGroup.LayoutParams params = chevronView.getLayoutParams();
        params.width = chevron_w;
        params.height = chevron_h;
        chevronView.setLayoutParams(params);

        float orig_card_height = (float)(cardArt.getHeight());
        float sx = chevron_h / (float)(cardArt.getWidth());
        float sy = chevron_w / orig_card_height;

        ScaleAnimation anim_scale = new ScaleAnimation(1.f, sx, 1.f, sy, ScaleAnimation.RELATIVE_TO_SELF, 0.5f, ScaleAnimation.RELATIVE_TO_SELF, 0.5f);
        RotateAnimation anim_rot = new RotateAnimation(0, -90.f, RotateAnimation.RELATIVE_TO_SELF, 0.5f, RotateAnimation.RELATIVE_TO_SELF, 0.5f);
        TranslateAnimation anim_trans = new TranslateAnimation(TranslateAnimation.RELATIVE_TO_SELF, 0.f, TranslateAnimation.RELATIVE_TO_SELF, 0.f,
                TranslateAnimation.RELATIVE_TO_SELF, 0.f, TranslateAnimation.RELATIVE_TO_SELF, sy * .5f);
        cardArtIntroAnimationSet = new AnimationSet(true);
        cardArtIntroAnimationSet.addAnimation(anim_scale);
        cardArtIntroAnimationSet.addAnimation(anim_rot);
        cardArtIntroAnimationSet.addAnimation(anim_trans);
        cardArtIntroAnimationSet.setDuration(1000);
        cardArtIntroAnimationSet.setFillEnabled(true);
        cardArtIntroAnimationSet.setFillAfter(true);
        cardArtIntroAnimationSet.setInterpolator(new AccelerateDecelerateInterpolator());
        cardArtIntroAnimationSet.setAnimationListener(new Animation.AnimationListener() {
            @Override
            public void onAnimationStart(Animation animation) {

            }

            @Override
            public void onAnimationEnd(Animation animation) {
                toggleArrowAnimation(false);
            }

            @Override
            public void onAnimationRepeat(Animation animation) {

            }
        });
        cardArt.startAnimation(cardArtIntroAnimationSet);

        Animation anim = AnimationUtils.loadAnimation(this, R.anim.tapnpay_status_show);
        anim.setDuration(1500);
        anim.setFillEnabled(true);
        anim.setFillBefore(true);
        anim.setFillAfter(true);
        anim.setInterpolator(new AccelerateDecelerateInterpolator());
        anim.setAnimationListener(new Animation.AnimationListener() {
            @Override
            public void onAnimationStart(Animation animation) {
                statusView.setVisibility(View.VISIBLE);
            }

            @Override
            public void onAnimationEnd(Animation animation) {
                toggleHelperText();
            }

            @Override
            public void onAnimationRepeat(Animation animation) {

            }
        });
        statusView.startAnimation(anim);

    }
    private void unRegisterTransactionReceiver(){
        if(transactionBroadcastReceiver != null){
            unregisterReceiver(transactionBroadcastReceiver);
            transactionBroadcastReceiver = null;
        }
    }

    public void loadAndPrepareSoundEffect() {
        this.setVolumeControlStream(AudioManager.STREAM_MUSIC);
        soundPool = new SoundPool(10, AudioManager.STREAM_MUSIC, 0);
        soundPool.setOnLoadCompleteListener(new SoundPool.OnLoadCompleteListener() {
            @Override
            public void onLoadComplete(SoundPool soundPool, int sampleId, int status) {
                soundIsReady = true;
            }
        });
        soundPaymentDone = soundPool.load(this, R.raw.salaciapaymentdone, 1);
        // Getting the user sound settings
        AudioManager audioManager = (AudioManager) getSystemService(AUDIO_SERVICE);
        float actualVolume = (float) audioManager.getStreamVolume(AudioManager.STREAM_MUSIC);
        float maxVolume = (float) audioManager.getStreamMaxVolume(AudioManager.STREAM_MUSIC);
        volume = actualVolume / maxVolume;
    }

    private void toggleHelperText() {
        statusView.setVisibility(View.GONE);
        statusView.setText("");
        nfcLogo.setVisibility(View.VISIBLE);
    }

    private void toggleArrowAnimation(final boolean isTransactionComplete) {
        recycleMemoryForAnimation();
        if(isTransactionComplete) {
            nfcLogo.setVisibility(View.GONE);
        }
        if (chevronView != null) {
            chevronView.setVisibility(View.VISIBLE);
            int animationResource = isTransactionComplete ? R.drawable.tag_discovered : R.drawable.tap_idle;
            chevronView.setBackgroundResource(animationResource);
            playChevronAnimation(isTransactionComplete);
        }
    }

    private void recycleMemoryForAnimation() {
        chevronView.setBackground(null);
    }

    private void playChevronAnimation(boolean isTransactionComplete) {
        Drawable chevron_background = chevronView.getBackground();
        if(chevron_background == null){
            return;
        }
        if(!(chevron_background instanceof AnimationDrawable)){
            return;
        }
        AnimationDrawable arrowAnimation = (AnimationDrawable)chevron_background;
        arrowAnimation.setVisible(true, true);
        arrowAnimation.setOneShot(isTransactionComplete);

        int n = arrowAnimation.getNumberOfFrames();
        int dur = 0;
        for (int i = 0; i < n; i++) {
            dur += arrowAnimation.getDuration(i);
        }
        final int duration = dur;
        final boolean transaction_complete = isTransactionComplete;
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                final Handler handler = new Handler();
                handler.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        if(transaction_complete){
                            playRestoreCartArtAnimation();
                        }
                    }
                }, duration);
            }
        });
        arrowAnimation.start();
    }
    private void playRestoreCartArtAnimation() {
        chevronView.setVisibility(View.GONE);
        recycleMemoryForAnimation();
        chevronView.setBackground(null);

        cardArtIntroAnimationSet.setInterpolator(new DIReverseInterpolator());
        cardArtIntroAnimationSet.setAnimationListener(new Animation.AnimationListener() {
            @Override
            public void onAnimationStart(Animation animation) {

            }

            @Override
            public void onAnimationEnd(Animation animation) {
                didRestoreCardArt();
            }

            @Override
            public void onAnimationRepeat(Animation animation) {

            }
        });
        cardArtIntroAnimationSet.setDuration(500);
        cardArt.startAnimation(cardArtIntroAnimationSet);
    }
    private void didRestoreCardArt(){
        if(soundIsReady) {
            soundPool.play(soundPaymentDone, volume, volume, 1, 0, 1f);
        }
        View rlComplete = findViewById(R.id.rlComplete);
        rlComplete.setVisibility(View.VISIBLE);
        AlphaAnimation anim = new AlphaAnimation(0.f, 1.f);
        anim.setDuration(500);
        anim.setFillEnabled(true);
        anim.setFillBefore(true);
        rlComplete.startAnimation(anim);

        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                final Handler handler = new Handler();
                handler.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        finish();
                        overridePendingTransition(R.anim.transition_flash_in, R.anim.transition_flash_out);
                    }
                }, 3000);
            }
        });
    }

    private void cancelPayment() {
        Toast.makeText(this, R.string.transaction_cancelled, Toast.LENGTH_SHORT).show();
        finish();
        overridePendingTransition(R.anim.transition_flash_in, R.anim.transition_flash_out);
    }

}
