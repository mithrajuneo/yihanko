package com.baby.ihanko;

import android.app.Activity;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.graphics.Color;
import android.view.Gravity;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setGravity(Gravity.CENTER);
        layout.setPadding(40, 40, 40, 40);
        layout.setBackgroundColor(Color.WHITE);

        TextView title = new TextView(this);
        title.setText("Babyihanko Bypass");
        title.setTextSize(24);
        title.setTextColor(Color.BLACK);
        title.setGravity(Gravity.CENTER);

        TextView description = new TextView(this);
        description.setText("\n✅ 버전 0.1v 모듈이 설치되었습니다.\n\n" +
                "사용 방법:\n" +
                "1. LSPosed 앱 열기\n" +
                "2. 모듈 탭에서 이 모듈 활성화\n" +
                "3. 적용 범위에서 루팅 우회할 앱 선택\n" +
                "4. 재부팅\n\n");
        description.setTextSize(14);
        description.setTextColor(Color.DKGRAY);
        description.setPadding(0, 20, 0, 0);

        layout.addView(title);
        layout.addView(description);

        setContentView(layout);
    }
}
