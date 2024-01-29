package com.example.keystorepablo.pantallas.common;


import com.example.keystorepablo.pantallas.principal.PrincipalController;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Data
@Component
public class BaseScreenController {

    private PrincipalController principalController;

    public void principalCargado() throws IOException {

    }

}
