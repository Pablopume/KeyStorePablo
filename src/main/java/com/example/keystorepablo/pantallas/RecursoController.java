package com.example.keystorepablo.pantallas;

import com.example.keystorepablo.domain.modelo.Credentials;
import com.example.keystorepablo.domain.modelo.Recurso;
import com.example.keystorepablo.pantallas.common.BaseScreenController;
import com.example.keystorepablo.servicios.ServicioCredentials;
import com.example.keystorepablo.servicios.ServicioRecurso;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;


import javafx.scene.control.cell.PropertyValueFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RecursoController extends BaseScreenController {
    public TableColumn<Recurso, Integer> id;
    public TableColumn<Recurso, String> firma;
    @FXML
    public TextField nombreRecurso;
@FXML
    public PasswordField contraseñaRecurso;
    public TableView<Recurso> recursosTable;
    public ComboBox<String> comboBox;
    public PasswordField newPassword;
    private Credentials credentials;
    private final ServicioCredentials servicioCredentials;
    private final ServicioRecurso servicioRecurso;

    public void initialize() {
        id.setCellValueFactory(new PropertyValueFactory<>("id"));
        firma.setCellValueFactory(new PropertyValueFactory<>("firma"));
        List<Credentials> credentialsList = servicioCredentials.getAll();
        for (Credentials credentials2 : credentialsList) {
            comboBox.getItems().add(credentials2.getUsername());
        }
    }

    public void setRecursosTable() {
        recursosTable.getItems().clear();
        List<Recurso> recursos2 = servicioRecurso.getAllRecursos(credentials.getUsername());
        for (Recurso recurso : recursos2) {
            recursosTable.getItems().add(recurso);
        }
    }

    @Autowired
    public RecursoController(ServicioCredentials servicioCredentials, ServicioRecurso servicioRecurso) {
        this.servicioCredentials = servicioCredentials;
        this.servicioRecurso = servicioRecurso;

    }


    public void crearRecurso() {
        servicioRecurso.crearRecurso(credentials.getUsername(), nombreRecurso.getText(), contraseñaRecurso.getText());
        setRecursosTable();
    }

    @Override
    public void principalCargado() {
        credentials = getPrincipalController().getActualCredentials();
        setRecursosTable();
    }

    public void compartirRecurso() {
        servicioRecurso.compartirRecurso(credentials.getUsername(), comboBox.getValue(), recursosTable.getSelectionModel().getSelectedItem());
    }

    public void verificarFirma()  {
        boolean respuesta = servicioRecurso.verificarFirmaRecurso(recursosTable.getSelectionModel().getSelectedItem(),credentials.getUsername() );
        Alert alert;

        if (respuesta) {
            alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Información sobre firma");
            alert.setHeaderText(null);
            alert.setContentText("Este usuario fue el ultimo en poner la contraseña");
        }
        else {
            alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Información sobre firma");
            alert.setHeaderText(null);
            alert.setContentText("Este usuario no fue el ultimo en poner la contraseña");
        }
        alert.showAndWait();
    }

    public void cambiarContrasenya() throws Exception {
        servicioRecurso.changePassword(credentials.getUsername(),newPassword.getText(),recursosTable.getSelectionModel().getSelectedItem());
    }
}