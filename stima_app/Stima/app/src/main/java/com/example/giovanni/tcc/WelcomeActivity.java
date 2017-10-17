package com.example.giovanni.tcc;

import android.content.Intent;
import android.os.CountDownTimer;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

public class WelcomeActivity extends AppCompatActivity {

    private String facilityID = "";

    private Bundle extras;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_welcome);

        /* get sent facility ID */
        extras = getIntent().getExtras();
        if(extras!=null){
            facilityID = (String) extras.get("facilityID");
        }

        /* sets a timer before redirecting to home */
        new CountDownTimer(15000, 1000) {

            public void onTick(long millisUntilFinished) {
            }

            public void onFinish() {
                Intent endWelcome = new Intent(WelcomeActivity.this, HomeActivity.class);
                endWelcome.putExtra("facilityID", facilityID);
                startActivity(endWelcome);
            }
        }.start();

    }
}
