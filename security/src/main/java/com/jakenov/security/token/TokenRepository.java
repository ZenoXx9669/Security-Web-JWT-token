package com.jakenov.security.token;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
@Transactional
public interface TokenRepository extends JpaRepository<Token, Long> {
    @Query("""
SELECT t FROM Token t inner join User u on t.user.id = u.id
WHERE u.id = :userId and (t.expired = false  or t.revoked = false )
""")
    List<Token> findAllByValidTokensByUser(Long userId);

    Optional<Token> findByToken(String token);
}
