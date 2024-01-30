package com.example.keystorepablo.seguridad.impl;

import lombok.Data;

@Data
public class ErrorApp {
    private String message;

    public ErrorApp(String message) {
        this.message = message;
    }


}
