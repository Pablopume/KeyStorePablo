package com.example.keystorepablo.domain.modelo;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Entity
@Table(name = Constantes.RECURSOS)
@AllArgsConstructor
@NoArgsConstructor
public class Recurso {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = Constantes.ID,nullable= false)
    private int id;
    @Column(name = Constantes.NOMBRES,nullable= false)
    private String nombre;
    @Column(name=Constantes.PASSWORD,nullable = false)
    private String password;
    @Column(name= Constantes.FIRMAR,nullable = false ,columnDefinition = Constantes.TEXT)
    private String firma;
    @Column(name= Constantes.FIRMA1,nullable = false)
    private String userfirma;
    @OneToMany(mappedBy = Constantes.RECURSOI)
    private List<Visualizador> visualizadores;
}
