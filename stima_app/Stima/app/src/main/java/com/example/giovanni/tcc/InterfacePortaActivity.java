package com.example.giovanni.tcc;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.util.Objects;

public class InterfacePortaActivity extends AppCompatActivity {

    private Button buttonAbrir;
    private TextView doorNumber;
    private EditText senhaPorta;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_interface_porta);

        buttonAbrir = (Button) findViewById(R.id.buttonAbrirId);
        doorNumber = (TextView) findViewById(R.id.doorNumberId);
        senhaPorta = (EditText) findViewById(R.id.editTextID);

        buttonAbrir.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                if(Objects.equals(senhaPorta.getText().toString(), "qwerasdf")){
                    Intent abrirIntent = new Intent(InterfacePortaActivity.this, EntradaActivity.class);
                    startActivity(abrirIntent);
                } else {
                    Intent denyIntent = new Intent(InterfacePortaActivity.this, EntradaNegadaActivity.class);
                    startActivity(denyIntent);
                }
            }
        });
    }
}
