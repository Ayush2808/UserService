package com.scaler.userservice.services;

import com.scaler.userservice.exceptions.UserNotFoundException;
import com.scaler.userservice.models.Token;
import com.scaler.userservice.models.User;
import com.scaler.userservice.repositories.TokenRepository;
import com.scaler.userservice.repositories.UserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;

@Service
public class UserService {
    private UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private TokenRepository tokenRepository;

    UserService(BCryptPasswordEncoder bCryptPasswordEncoder, UserRepository userRepository, TokenRepository tokenRepository) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
    }
    public User SignUp(String name, String email, String password){



         User user = new User();
         user.setName(name);
         user.setEmail(email);
         user.setHashedPassword(bCryptPasswordEncoder.encode(password));
         user.setEmailVerified(true);
         userRepository.save(user);


         return null;
    }
    public Token login(String email, String password){
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if(optionalUser.isEmpty()){
                throw new UserNotFoundException("User with email " + email + "does not exist");
        }

        User user = optionalUser.get();
        if(!bCryptPasswordEncoder.matches(password, user.getHashedPassword())){
            //Throw some Exceptions
            return null;
        }
        //Login Successful, generate a token
       // Token token =
        Token token = new Token();
        Token savedToken = tokenRepository.save(token);

        return savedToken;

    }
    private Token generateToken(User user) {
        LocalDate currentDate = LocalDate.now();
        LocalDate thirtyDaysLater = currentDate.plusDays(30);

        Date expiryDate = Date.from(thirtyDaysLater.atStartOfDay(ZoneId.systemDefault()).toInstant());
        Token token = new Token();
        token.setExpiryAt(expiryDate);
        token.setValue(RandomStringUtils.randomAlphanumeric(128));
        token.setUser(user);
        return token;
    }

    public void logout(String tokenValue) {
        Optional<Token> optionalToken = tokenRepository.findByValueAndDeleted(tokenValue, false);
        if (optionalToken.isEmpty()) {
            return; // Token not found or already deleted
        }

        Token token = optionalToken.get();
        token.setDeleted(true); // Mark the token as deleted
        tokenRepository.save(token); // Persist changes
    }


    public User validateToken(String token) {
        Optional<Token> optionalToken = tokenRepository.findByValueAndDeletedAndExpiryAtGreaterThan(token, false, new Date());
        if(optionalToken.isEmpty()){
            return null;
        }
        return optionalToken.get().getUser();
    }



}
