package com.example.keystorepablo.data;

import com.example.keystorepablo.domain.modelo.Recurso;
import com.example.keystorepablo.domain.modelo.Visualizador;
import org.springframework.data.repository.ListCrudRepository;

import java.util.List;

public interface VisualizadorRepository
    extends ListCrudRepository<Visualizador, String>{
    Visualizador findByNombreAndRecurso(String nombre, Recurso recurso);
    List<Visualizador> findByNombre(String nombre);
    Visualizador findVisualizadorByRecursoAndNombre(Recurso recurso,String nombre);
}
