package com.example.keystorepablo.data;

import com.example.keystorepablo.domain.modelo.Credentials;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CredentialsRepository extends ListCrudRepository<Credentials, String> {
Credentials findByUsername(String username);

}
