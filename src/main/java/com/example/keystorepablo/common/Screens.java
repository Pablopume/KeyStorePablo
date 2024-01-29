package com.example.keystorepablo.common;

public enum Screens {

    SCREENCUSTOMERS(Constants.FXML_CUSTOMERS_LIST_CUSTOMERS_FXML),
    SCREENADD(Constants.FXML_CUSTOMERS_ADD_CUSTOMERS_FXML),
    LOGIN(Constants.FXML_LOGIN_FXML),
    SCREENREMOVE(Constants.FXML_CUSTOMERS_DELETE_CUSTOMERS_FXML),
    SCREENEDIT(Constants.FXML_CUSTOMERS_EDIT_CUSTOMERS_FXML),
    PANTALLAORDERS(Constants.FXML_ORDERS_LIST_ORDERS_FXML),
    ADDORDERS(Constants.FXML_ORDERS_ADD_ORDERS_FXML),

    REMOVEORDERS(Constants.FXML_ORDERS_DELETE_ORDERS_FXML),
    EDITORDERS(Constants.FXML_ORDERS_EDIT_ORDERS_FXML),

    NEWSCREEN(Constants.FXML_PANTALLA_NUEVA_FXML),
    SCREENRECURSOS("/fxml/recursos.fxml");

    private String route;

    Screens(String ruta) {
        this.route = ruta;
    }

    public String getRoute() {
        return route;
    }



}
