package com.example.keystorepablo.common;

public enum Screens {


    LOGIN(Constants.FXML_LOGIN_FXML),

    SCREENRECURSOS(Constants.RECURSOSFXML);

    private String route;

    Screens(String ruta) {
        this.route = ruta;
    }

    public String getRoute() {
        return route;
    }



}
