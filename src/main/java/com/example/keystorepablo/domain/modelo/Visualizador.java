package com.example.keystorepablo.domain.modelo;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@Table(name = "visualizadores")
@AllArgsConstructor
@NoArgsConstructor
public class Visualizador {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id",nullable= false)
    private int id;
    @Column(name = "nombre",nullable= false)
    private String nombre;
    @Column(name = "password",nullable= false,columnDefinition = "TEXT")
    private String password;
    @ManyToOne
    @JoinColumn(name = "recurso_id")
    private Recurso recurso;
}
