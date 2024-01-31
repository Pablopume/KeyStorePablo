package com.example.keystorepablo;

import com.example.keystorepablo.common.Constants;
import javafx.fxml.FXMLLoader;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
@Log4j2
@org.springframework.context.annotation.Configuration
public class Configuration {
    private final Properties p;
    @Bean
    public FXMLLoader createLoader(ApplicationContext context) {
        FXMLLoader loader = new FXMLLoader();
        loader.setControllerFactory(context::getBean);
        return loader;
    }

    public Configuration() {
        Path p1 = Paths.get(Constants.SRC_MAIN_RESOURCES_MYSQL_PROPERTIES_XML);
        p = new Properties();
        InputStream propertiesStream;
        try {
            propertiesStream = Files.newInputStream(p1);
            p.loadFromXML(propertiesStream);
        } catch (IOException e) {
            log.error(e.getMessage());
        }
    }

    public String getProperty(String clave) {
        return p.getProperty(clave);
    }
    @Bean
    public PasswordEncoder createPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }
}
