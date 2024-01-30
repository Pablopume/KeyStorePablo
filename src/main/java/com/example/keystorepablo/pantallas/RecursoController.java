package com.example.keystorepablo.pantallas;

import com.example.keystorepablo.domain.modelo.Credentials;
import com.example.keystorepablo.domain.modelo.Recurso;
import com.example.keystorepablo.pantallas.common.BaseScreenController;
import com.example.keystorepablo.servicios.ServicioCredentials;
import com.example.keystorepablo.servicios.ServicioRecurso;
import javafx.scene.control.*;


import javafx.scene.control.cell.PropertyValueFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RecursoController extends BaseScreenController {
    public TableColumn<Recurso, Integer> id;
    public TableColumn<Recurso, String> firma;
    public TextField nombreRecurso;

    public PasswordField contraseñaRecurso;
    public TableView<Recurso> recursosTable;
    public ComboBox<String> comboBox;
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

    public void verificarFirma() throws Exception {
        boolean respuesta = servicioRecurso.verificarFirmaRecurso(recursosTable.getSelectionModel().getSelectedItem(),credentials.getUsername() );
        if (respuesta) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Contraseña correcta");
            alert.setHeaderText(null);
            alert.setContentText("La contraseña es correcta");
            alert.showAndWait();
        }
    }
}