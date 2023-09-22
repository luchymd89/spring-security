package com.steppenwolf.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // Added when using  @PreAuthorize
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception{
       http
               // If the services are going to be used by a browse enable csrf, uncomment these two lines
               //.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
               //.and()
               .csrf().disable()
               .authorizeRequests()
               // Order antMatchers matters
               .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
               .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
               //Equivalent @PreAuthorize in StudentManagementController
             //  .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicationUserPermission.STUDENT_WRITE.getPermission())
             //  .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(ApplicationUserPermission.STUDENT_WRITE.getPermission())
              // .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicationUserPermission.STUDENT_WRITE.getPermission())
             //  .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
               .anyRequest()
               .authenticated()
               .and()
               .httpBasic();
    }


    @Override
    @Bean
    protected UserDetailsService userDetailsService(){
        UserDetails studentUser = User.builder()
                .username("user_student")
                .password(passwordEncoder.encode("password_student"))
                //.roles(ApplicationUserRole.STUDENT.name()) // ROLE_STUDENT
                .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
                .build();

        UserDetails adminUser = User.builder()
                .username("user_admin")
                .password(passwordEncoder.encode("password_admin"))
                //.roles(ApplicationUserRole.ADMIN.name()) // ROLE_ADMIN
                .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
                .build();

        UserDetails adminTraineeUser = User.builder()
                .username("user_admintrainee")
                .password(passwordEncoder.encode("password_admintrainee"))
                //.roles(ApplicationUserRole.ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
                .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(studentUser, adminUser, adminTraineeUser);

    }

}
