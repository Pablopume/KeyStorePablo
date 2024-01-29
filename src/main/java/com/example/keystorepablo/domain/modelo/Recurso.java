package com.example.keystorepablo.domain.modelo;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Entity
@Table(name = "recursos")
@AllArgsConstructor
@NoArgsConstructor
public class Recurso {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id",nullable= false)
    private int id;
    @Column(name = "nombre",nullable= false)
    private String nombre;

    @Column(name="password",nullable = false)
    private String password;
    @Column(name="firma",nullable = false ,columnDefinition = "TEXT")
    private String firma;
    @Column(name="user_firma",nullable = false,columnDefinition = "LONGTEXT")
    private String userfirma;
    @OneToMany(mappedBy = "recurso")
    private List<Visualizador> visualizadores;
}
