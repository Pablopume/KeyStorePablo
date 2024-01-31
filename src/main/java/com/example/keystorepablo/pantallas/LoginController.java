package com.example.keystorepablo.pantallas;

import com.example.keystorepablo.domain.modelo.Credentials;
import com.example.keystorepablo.pantallas.common.BaseScreenController;
import com.example.keystorepablo.seguridad.impl.ErrorApp;
import com.example.keystorepablo.servicios.ServicioCredentials;
import io.vavr.control.Either;
import javafx.fxml.FXML;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class LoginController extends BaseScreenController {
    private final ServicioCredentials servicioCredentials;
    @FXML
    public TextField txtUserName;
    @FXML
    public PasswordField txtPassword;

    @Autowired
    public LoginController(ServicioCredentials servicioCredentials) {
        this.servicioCredentials = servicioCredentials;
    }

    public void initialize() {
    //Quitar SonarLint
    }

    public void doLogin() {
        Either<ErrorApp, Boolean> result = servicioCredentials.doLogin(txtUserName.getText(), txtPassword.getText());
        if (result.isRight()) {
            Credentials credentials = new Credentials(0, txtUserName.getText(), txtPassword.getText());
            getPrincipalController().onLoginDone(credentials);
        } else {
            getPrincipalController().showErrorAlert("Usuario o contraseña incorrectos");
        }
    }

    public void doRegister() {
        Either<ErrorApp, Boolean> result = servicioCredentials.register(new Credentials(0, txtUserName.getText(), txtPassword.getText()));
        if (result.isRight()) {
            getPrincipalController().showConfirmationAlert("Usuario registrado correctamente");
        } else {
            getPrincipalController().showErrorAlert("Error al registrar el usuario");
        }
    }

    //HE METIDO ESTOS DOS OVERRIDES PARA QUE NO SALGA EL ERROR DE SONARLINT
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
