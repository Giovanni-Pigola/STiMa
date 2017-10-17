package com.example.giovanni.tcc;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class InterfacePortaActivity extends AppCompatActivity {

    private Button buttonAbrir;
    private TextView doorNumber;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_interface_porta);

        buttonAbrir = (Button) findViewById(R.id.buttonAbrirId);
        doorNumber = (TextView) findViewById(R.id.doorNumberId);

        buttonAbrir.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                Intent abrirIntent = new Intent(InterfacePortaActivity.this, EntradaActivity.class);
                startActivity(abrirIntent);

            }
        });

        doorNumber.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                Intent denyIntent = new Intent(InterfacePortaActivity.this, EntradaNegadaActivity.class);
                startActivity(denyIntent);

            }
        });

    }
}
