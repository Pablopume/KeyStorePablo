package com.example.keystorepablo.domain.modelo;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@Table(name = Constantes.VISUALIZADORES)
@AllArgsConstructor
@NoArgsConstructor
public class Visualizador {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = Constantes.ID,nullable= false)
    private int id;
    @Column(name = Constantes.NOMBRES,nullable= false)
    private String nombre;
    @Column(name = Constantes.PASSWORD,nullable= false,columnDefinition = Constantes.TEXT)
    private String password;
    @ManyToOne
    @JoinColumn(name = Constantes.RECURSO_ID, referencedColumnName = Constantes.ID)
    private Recurso recurso;
}
