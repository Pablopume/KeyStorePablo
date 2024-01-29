package com.example.keystorepablo.domain.modelo;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@Table(name = "credentials")
@AllArgsConstructor
@NoArgsConstructor
public class Credentials {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id",nullable= false)
    private int id;
    @Column(name = "username",nullable= false)
    private String username;
    @Column(name = "password",nullable= false)
    private String password;


}
