package com.example.keystorepablo.data;

import com.example.keystorepablo.domain.modelo.Recurso;
import org.springframework.data.repository.ListCrudRepository;

import java.util.List;

public interface RecursoRepsitory extends ListCrudRepository<Recurso, String> {

}
