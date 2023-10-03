package com.steppenwolf.springsecurity.security;

import com.steppenwolf.springsecurity.auth.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // Added when using  @PreAuthorize
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{

    private final PasswordEncoder passwordEncoder;

    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
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
               //.httpBasic(); For Basic Authentication
                .formLogin() // For Form Based Authentication
                    .loginPage("/login")
                    .permitAll() // Login page
                    .defaultSuccessUrl("/courses", true) //Redirect to start page
                   // .usernameParameter("username") // Default value username, dont need it. If change it in login.html name="unnombre" value
                   // .passwordParameter("password")  // Default value password, dont need it
                .and()
                .rememberMe() //Default to 2 weeks
                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21)) // Extend the session to 21 days
                    .key("somethingverysecure") //Key for hash to store the token
                    //.rememberMeParameter("remember-me")  // Default value remember-me, dont need it
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // Comment this line if csrf is enable
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");

    }


    // Commented in order to use ApplicationUserService
    /*@Override
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

    }*/


    // Needed to use ApplicationUserService
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    // Needed to use ApplicationUserService
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);

        return provider;

    }

}
