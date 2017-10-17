package com.example.giovanni.tcc;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class NFCtesteActivity extends AppCompatActivity {

    private Button buttonNFC;
    private TextView textoTitulo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_nfcteste);

        //definir as permissões aqui e no manifest

        buttonNFC = (Button) findViewById(R.id.NFCbuttonID);
        textoTitulo = (TextView) findViewById(R.id.NFCtituloID);

        buttonNFC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //escrever os codigos do botão aqui pra ler o NFC
            }
        });

    }
}
