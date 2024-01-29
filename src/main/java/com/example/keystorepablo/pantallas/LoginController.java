package com.example.keystorepablo.pantallas;

import com.example.keystorepablo.domain.modelo.Credentials;
import com.example.keystorepablo.pantallas.common.BaseScreenController;
import com.example.keystorepablo.servicios.ServicioCredentials;
import javafx.event.ActionEvent;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class LoginController extends BaseScreenController {
    private final ServicioCredentials servicioCredentials;
    public TextField txtUserName;
    public PasswordField txtPassword;

    @Autowired
    public LoginController(ServicioCredentials servicioCredentials) {
        this.servicioCredentials = servicioCredentials;
    }

    public void initialize() {

    }

    public void doLogin(ActionEvent actionEvent) {
        if (servicioCredentials.doLogin(txtUserName.getText(), txtPassword.getText())) {
            Credentials credentials=new Credentials(0,txtUserName.getText(),txtPassword.getText());
            getPrincipalController().onLoginDone(credentials);
        } else {

        }
    }

    public void doRegister() {
        servicioCredentials.register(new Credentials(0, txtUserName.getText(), txtPassword.getText()));
    }
}
