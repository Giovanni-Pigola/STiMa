package com.example.giovanni.tcc;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;

public class MapaDeCalorActivity extends AppCompatActivity {

    private Button mapButton;
    private Button statButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_mapa_de_calor);

        mapButton = (Button) findViewById(R.id.buttonHeatMapID);
        statButton = (Button) findViewById(R.id.buttonStatisticsID);

        mapButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent geraMapa = new Intent(MapaDeCalorActivity.this, HeatMap.class);
                startActivity(geraMapa);
            }
        });

        statButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent geraStat = new Intent(MapaDeCalorActivity.this, Statistics.class);
                startActivity(geraStat);
            }
        });

    }
}
