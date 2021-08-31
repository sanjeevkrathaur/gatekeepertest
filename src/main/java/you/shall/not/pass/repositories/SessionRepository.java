package you.shall.not.pass.repositories;

import org.springframework.data.mongodb.repository.MongoRepository;
import you.shall.not.pass.domain.Session;

import java.util.Optional;

public  interface SessionRepository extends MongoRepository<Session, String> {

    Optional<Session> findSessionByToken(String token);

}
