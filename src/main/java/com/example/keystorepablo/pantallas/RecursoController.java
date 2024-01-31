package com.example.keystorepablo.pantallas;
import com.example.keystorepablo.domain.modelo.Credentials;
import com.example.keystorepablo.domain.modelo.Recurso;
import com.example.keystorepablo.pantallas.common.BaseScreenController;
import com.example.keystorepablo.seguridad.impl.ErrorApp;
import com.example.keystorepablo.servicios.ServicioCredentials;
import com.example.keystorepablo.servicios.ServicioRecurso;
import io.vavr.control.Either;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RecursoController extends BaseScreenController {
    @FXML
    private TableColumn<Recurso, Integer> id;

    @FXML
    private TableColumn<Recurso, String> firma;
    @FXML
    private TextField nombreRecurso;
    @FXML
    private PasswordField contrasenyaRec;
    @FXML
    private TableView<Recurso> recursosTable;
    @FXML
    public ComboBox<String> comboBox;
    @FXML
    public PasswordField newPassword;
    private Credentials credentials;
    private final ServicioCredentials servicioCredentials;
    private final ServicioRecurso servicioRecurso;

    public void initialize() {
        id.setCellValueFactory(new PropertyValueFactory<>(ConstantesPantalla.ID));
        firma.setCellValueFactory(new PropertyValueFactory<>(ConstantesPantalla.FIRMA));
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
        Either<ErrorApp, Recurso> result =
        servicioRecurso.crearRecurso(credentials.getUsername(), nombreRecurso.getText(), contrasenyaRec.getText());
        if (result.isRight()) {
            getPrincipalController().showConfirmationAlert(ConstantesPantalla.RECURSO_CREADO_CORRECTAMENTE);
            setRecursosTable();
        } else {
            getPrincipalController().showErrorAlert(result.getLeft().getMessage());
        }

    }

    @Override
    public void principalCargado() {
        credentials = getPrincipalController().getActualCredentials();
        setRecursosTable();
    }

    public void compartirRecurso() {
        servicioRecurso.compartirRecurso(credentials.getUsername(), comboBox.getValue(), recursosTable.getSelectionModel().getSelectedItem());
    }

    public void verificarFirma() {
        Either<ErrorApp, Boolean> result = servicioRecurso.verificarFirmaRecurso(recursosTable.getSelectionModel().getSelectedItem(), credentials.getUsername());
        Alert alert;

        if (result.isRight()) {
            if (Boolean.TRUE.equals(result.get())) {
                alert = new Alert(Alert.AlertType.INFORMATION);
                alert.setTitle(ConstantesPantalla.FIRMA1);
                alert.setHeaderText(null);
                alert.setContentText(ConstantesPantalla.ESTE_USUARIO_FUE_EL_ULTIMO_EN_PONER_LA_CONTRASENYA);
            } else {
                alert = new Alert(Alert.AlertType.ERROR);
                alert.setTitle(ConstantesPantalla.FIRMA1);
                alert.setHeaderText(null);
                alert.setContentText(ConstantesPantalla.ESTE_USUARIO_NO_FUE_EL_ULTIMO_EN_PONER_LA_CONTRASENYA);
            }
            alert.showAndWait();
        } else {
            getPrincipalController().showErrorAlert(result.getLeft().getMessage());
        }
    }

    public void cambiarContrasenya() throws Exception {
        Either<ErrorApp, Boolean> result = servicioRecurso.changePassword(credentials.getUsername(), newPassword.getText(), recursosTable.getSelectionModel().getSelectedItem());
        if (result.isRight()) {
            getPrincipalController().showConfirmationAlert(ConstantesPantalla.CONTRASENYA_CAMBIADA_CORRECTAMENTE);
        } else {
            getPrincipalController().showErrorAlert(result.getLeft().getMessage());
        }
    }



    //HE METIDO ESTOS DOS OVERRIDES PORQUE SINO ME DA UN ERROR DE SONARLINT
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}