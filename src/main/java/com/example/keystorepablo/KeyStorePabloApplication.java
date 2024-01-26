package com.example.keystorepablo;

import javafx.application.Application;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class KeyStorePabloApplication {

    public static void main(String[] args) {
        Application.launch(DIJavafx.class, args);
//        SpringApplication.run(KeyStorePabloApplication.class, args);
    }

}
