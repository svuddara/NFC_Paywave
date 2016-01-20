package nfc.visa.com.nfc.util;

import android.view.animation.Interpolator;

/**
 * Created by cjiang on 5/21/15.
 */
public class DIReverseInterpolator implements Interpolator {
    @Override
    public float getInterpolation(float paramFloat) {
        return Math.abs(paramFloat - 1f);
    }
}