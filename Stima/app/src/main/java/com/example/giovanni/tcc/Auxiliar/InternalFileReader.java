package com.example.giovanni.tcc.Auxiliar;

import android.util.Log;

import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.SequenceInputStream;

/**
 * Created by Giovanni on 18/08/2017.
 */

public class InternalFileReader {

    private String s = "";
    private String cp = "";

    // Read text from file
    public String readFile(FileInputStream openFileIn) {
        //reading text from file
        try {
            InputStreamReader InputRead= new InputStreamReader(openFileIn);

            char[] inputBuffer= new char[10000];

            int charRead;

            while ((charRead=InputRead.read(inputBuffer))>0) {
                String readstring = String.copyValueOf(inputBuffer,0,charRead);
                s +=readstring;
            }
            InputRead.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
        cp = s;
        s = "";
        return cp;
    }

}
