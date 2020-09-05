package com.google.ctf.sandbox;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

/* renamed from: com.google.ctf.sandbox.ő */
public class C0007 extends Activity {

    /* renamed from: class  reason: not valid java name */
    long[] f8class;

    /* renamed from: ő */
    int f6;

    /* renamed from: ő */
    long[] f7;

    public C0007() {
        try {
            this.f8class = new long[]{40999019, 2789358025L, 656272715, 18374979, 3237618335L, 1762529471, 685548119, 382114257, 1436905469, 2126016673, 3318315423L, 797150821};
            this.f7 = new long[12];
            this.f6 = 0;
        } catch (I unused) {
        }
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(C0006R.layout.activity_main);
        final EditText editText = (EditText) findViewById(C0006R.id.editText);
        final TextView textView = (TextView) findViewById(C0006R.id.textView);
        ((Button) findViewById(C0006R.id.button)).setOnClickListener(new View.OnClickListener() {
            /* class com.google.ctf.sandbox.C0007.C00081 */

            public void onClick(View v) {
                C0007.this.f6 = 0;
                try {
                    StringBuilder keyString = new StringBuilder();
                    for (Object chr : new Object[]{65, 112, 112, 97, 114, 101, 110, 116, 108, 121, 32, 116, 104, 105, 115, 32, 105, 115, 32, 110, 111, 116, 32, 116, 104, 101, 32, 102, 108, 97, 103, 46, 32, 87, 104, 97, 116, 39, 115, 32, 103, 111, 105, 110, 103, 32, 111, 110, 63}) {
                        keyString.append(((Character) chr).charValue());
                    }
                    if (editText.getText().toString().equals(keyString.toString())) {
                        textView.setText("🚩");
                    } else {
                        textView.setText("❌");
                    }
                } catch (J | Error | Exception unused) {
                    String flagString = editText.getText().toString();
                    if (flagString.length() != 48) {
                        textView.setText("❌");
                        return;
                    }
                    for (int i = 0; i < flagString.length() / 4; i++) {
                        C0007.this.f7[i] = (long) (flagString.charAt((i * 4) + 3) << 24);
                        long[] jArr = C0007.this.f7;
                        jArr[i] = jArr[i] | ((long) (flagString.charAt((i * 4) + 2) << 16));
                        long[] jArr2 = C0007.this.f7;
                        jArr2[i] = jArr2[i] | ((long) (flagString.charAt((i * 4) + 1) << 8));
                        long[] jArr3 = C0007.this.f7;
                        jArr3[i] = jArr3[i] | ((long) flagString.charAt(i * 4));
                    }
                    C0007 r6 = C0007.this;
                    if (((C0006R.m0(C0007.this.f7[C0007.this.f6], 4294967296L)[0] % 4294967296L) + 4294967296L) % 4294967296L != C0007.this.f8class[C0007.this.f6]) {
                        textView.setText("❌");
                        return;
                    }
                    C0007.this.f6++;
                    if (C0007.this.f6 >= C0007.this.f7.length) {
                        textView.setText("🚩");
                        return;
                    }
                    throw new RuntimeException();
                }
            }
        });
    }
}
