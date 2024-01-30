package com.example.keystorepablo.pantallas.principal;

import com.example.keystorepablo.common.Screens;
import com.example.keystorepablo.domain.modelo.Credentials;
import com.example.keystorepablo.pantallas.common.BaseScreenController;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.ApplicationContext;

import org.springframework.stereotype.Component;

import java.io.IOException;
@Data
@Log4j2
@Component
public class PrincipalController {

    private final ApplicationContext context;
    private Credentials actualCredentials;
    private Alert alert;
    @FXML
    private BorderPane root;
    private Stage primaryStage;

    public PrincipalController(ApplicationContext context) {
        this.context = context;
        actualCredentials = null;
    }


    public void initialize() {
        cargarPantalla(Screens.LOGIN.getRoute());

        alert = new Alert(Alert.AlertType.NONE);
    }

    public void setStage(Stage stage) {
        primaryStage = stage;
    }

    public void onLoginDone(Credentials user) {
        actualCredentials = user;
        cargarPantalla(Screens.SCREENRECURSOS.getRoute());
    }

    public void exit() {
        root.getScene().getWindow().fireEvent(new WindowEvent(root.getScene().getWindow(), WindowEvent.WINDOW_CLOSE_REQUEST));
    }

    public void logout() {
        actualCredentials = null;
        cargarPantalla(Screens.LOGIN.getRoute());
    }

    public void showErrorAlert(String mensaje) {
        alert.setAlertType(Alert.AlertType.ERROR);
        alert.setContentText(mensaje);
        alert.getDialogPane().setId("alert");
        alert.getDialogPane().lookupButton(ButtonType.OK).setId("btn-ok");
        alert.showAndWait();
    }

    public void showConfirmationAlert(String mensaje) {
        alert.setAlertType(Alert.AlertType.INFORMATION);
        alert.setContentText(mensaje);
        alert.setHeaderText(mensaje);
        alert.getDialogPane().lookupButton(ButtonType.OK).setId("btn-ok");
        alert.showAndWait();
    }

    private Pane cargarPantalla(String ruta) {
        Pane panePantalla = null;
        try {
            FXMLLoader fxmlLoader = new FXMLLoader();
            fxmlLoader.setControllerFactory(context::getBean);
            panePantalla = fxmlLoader.load(getClass().getResourceAsStream(ruta));
            root.setCenter(panePantalla);
            BaseScreenController baseScreenController = fxmlLoader.getController();
            baseScreenController.setPrincipalController(this);
            baseScreenController.principalCargado();

        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
        return panePantalla;
    }

    public void logOutClick() {
        logout();
    }
}