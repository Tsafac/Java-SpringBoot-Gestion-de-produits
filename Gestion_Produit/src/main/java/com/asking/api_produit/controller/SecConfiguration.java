package com.asking.api_produit.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.asking.api_produit.service.CustomUserDetailsService;

@Configuration
@EnableWebSecurity
public class SecConfiguration extends WebSecurityConfigurerAdapter {

    /**
     * Mot de passe admin injecté depuis une variable d’environnement Kubernetes
     * (Secret)
     */
    @Value("${ADMIN_PASSWORD}")
    private String adminPassword;

    // Service de gestion des utilisateurs (BDD)
    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailsService();
    }

    // Encodeur de mot de passe
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Provider d’authentification
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        // Authentification via la base de données
        auth.authenticationProvider(authenticationProvider());

        // Compte admin en mémoire (mot de passe injecté via Secret)
        auth.inMemoryAuthentication()
            .passwordEncoder(passwordEncoder())
            .withUser("Charbel")
            .password(passwordEncoder().encode(adminPassword))
            .roles("admin");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
            .authorizeRequests()
                .antMatchers(
                    "/listeAvecCon",
                    "/creation/",
                    "/saveProduct",
                    "/maj/*",
                    "/delete/*"
                ).authenticated()
                .antMatchers("/users", "/deleteUser/*").hasRole("admin")
                .anyRequest().permitAll()
            .and()
            .formLogin()
                .usernameParameter("email")
                .defaultSuccessUrl("/listeAvecCon")
                .permitAll()
            .and()
            .logout()
                .logoutSuccessUrl("/")
                .permitAll();
    }
}
