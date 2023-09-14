package com.example.securityspring.config;

import com.example.securityspring.jwt.JwtAccessDeniedHandler;
import com.example.securityspring.jwt.JwtAuthenticationEntryPoint;
import com.example.securityspring.jwt.JwtSecurityConfig;
import com.example.securityspring.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.*;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final TokenProvider tokenProvider;
    //private final CorsFilter corsFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(TokenProvider tokenProvider, JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint, JwtAccessDeniedHandler jwtAccessDeniedHandler) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(HandlerMappingIntrospector introspector) {
        return (web) -> web.ignoring()
                // Spring Security should completely ignore URLs starting with /resources/
                .requestMatchers(new AntPathRequestMatcher("/h2-console/**"))
                .requestMatchers(new MvcRequestMatcher.Builder(introspector).pattern("/favicon.ico"));
                //.requestMatchers("/h2-console/**");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {


        MvcRequestMatcher.Builder h2RequestMatcher = new MvcRequestMatcher.Builder(introspector);
        http
                .csrf(csrf -> csrf.disable())
                //.addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exceptionHandling -> exceptionHandling.accessDeniedHandler(jwtAccessDeniedHandler).authenticationEntryPoint(jwtAuthenticationEntryPoint))
                .authorizeHttpRequests((authz) -> authz
                        //.requestMatchers("/favicon.ico").authenticated()
                        //.requestMatchers("/h2-console/**/**").permitAll()
                        //.requestMatchers(new AntPathRequestMatcher("/h2-console/**/**")).permitAll()
                        //.requestMatchers(PathRequest.toH2Consol e()).permitAll()
                        //.requestMatchers("/api/hello").permitAll()
                        //.requestMatchers(new MvcRequestMatcher(introspector,"/api/hello")).permitAll()
                        .requestMatchers(h2RequestMatcher.pattern("/api/hello")).permitAll()
                        .requestMatchers(h2RequestMatcher.pattern("/api/signup")).permitAll()
                        /*.requestMatchers(h2RequestMatcher.pattern("/api/authenticate")).permitAll()*/
                        .anyRequest().authenticated())

// 세션을 사용하지 않기 때문에 STATELESS로 설정
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // enable h2-console
                .headers(headers ->
                        headers.frameOptions(options ->
                                options.sameOrigin()
                        )
                )

                .apply(new JwtSecurityConfig(tokenProvider));
                //.csrf((csrf) -> csrf.ignoringRequestMatchers("/h2-console/**"))
        //.httpBasic(Customizer.withDefaults());
        return http.build();
    }

    /*@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests().requestMatchers("/public/**").permitAll().anyRequest()
                .hasRole("USER").and()
                // Possibly more configuration ...
                .formLogin() // enable form based log in
                // set permitAll for all URLs associated with Form Login
                .permitAll();
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN", "USER")
                .build();
        return new InMemoryUserDetailsManager(user, admin);
    }*/

    // Possibly more bean methods ...
}
