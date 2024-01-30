package com.example.keystorepablo.pantallas;

import com.example.keystorepablo.domain.modelo.Credentials;
import com.example.keystorepablo.domain.modelo.Recurso;
import com.example.keystorepablo.pantallas.common.BaseScreenController;
import com.example.keystorepablo.servicios.ServiceVisualizador;
import com.example.keystorepablo.servicios.ServicioRecurso;
import javafx.event.ActionEvent;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class RecursoController extends BaseScreenController {
    private Credentials credentials;
    private final ServicioRecurso servicioRecurso;
    private final ServiceVisualizador serviceVisualizador;
    public TextArea cifrado;
    public TextField txtNormal;

    @Autowired
    public RecursoController(ServicioRecurso servicioRecurso, ServiceVisualizador serviceVisualizador) {

        this.servicioRecurso = servicioRecurso;
        this.serviceVisualizador = serviceVisualizador;
    }


    public void cifrar(ActionEvent actionEvent) {
    }

    public void descrifrar(ActionEvent actionEvent) {
    }

    public void crearCertificados() throws Exception {
        servicioRecurso.crearVisualizador(servicioRecurso.crearRecurso(credentials.getUsername(), "recurso1", "1234"), credentials.getUsername());

    }

    @Override
    public void principalCargado() {
        credentials = getPrincipalController().getActualCredentials();
    }
}