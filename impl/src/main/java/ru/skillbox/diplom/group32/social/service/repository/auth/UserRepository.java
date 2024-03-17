package ru.skillbox.diplom.group32.social.service.repository.auth;

import org.springframework.stereotype.Repository;
import ru.skillbox.diplom.group32.social.service.model.auth.User;
import ru.skillbox.diplom.group32.social.service.repository.base.BaseRepository;

import java.util.Optional;

@Repository
public interface UserRepository extends BaseRepository<User> {

    Optional<User> findUserByEmail(String email);

}
