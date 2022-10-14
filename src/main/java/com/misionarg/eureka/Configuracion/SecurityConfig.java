package com.misionarg.eureka.Configuracion;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter{

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		// TODO Auto-generated method stub
		return super.authenticationManagerBean();
	}


	/*
	@Autowired
	private DataSource dataSource;
*/

	//definición roles y usuarios
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		auth
				.inMemoryAuthentication()
				.withUser("admin")
				.password("{noop}admin")
				//.password(pw1)
				.roles("ADMIN");


		/*auth
				.jdbcAuthentication()
					.dataSource(dataSource)
					.passwordEncoder(bCryptPasswordEncoder)
					.usersByUsernameQuery("select usuario, pass, activo from usuario where usuario = ?")
					.authoritiesByUsernameQuery("select u.usuario as usuario, ur.rol from \n" +
							"(select * from Usuario) u inner join \n" +
							"(select * from usuarioRol) ur on u.idBoletero = ur.idusuario where usuario =  ?");

	}

        .inMemoryAuthentication()
        .withUser("user1")
          .password("{noop}user1") //lo de {noop} se pone para no obligar a usar mecanismo de encriptación
          .roles("USER")
          .and()
        .withUser("admin")
          .password("{noop}admin")
          .roles("USER", "ADMIN");
*/
		/*lo siguiente sería para el caso de que
		 * quisiéramos encriptar la password:
		String pw1=new BCryptPasswordEncoder().encode("user1");
		System.out.println(pw1);
		  auth
	        .inMemoryAuthentication()
	        .withUser("user1")
	          .password("{bcrypt}"+pw1)
	          //.password(pw1)
	          .roles("USER")
	          .and()
	        .withUser("admin")
	          .password(new BCryptPasswordEncoder().encode("admin"))
	          .roles("USER", "ADMIN");
		 */
		
		/*la seguiente configuración será para el caso de 
		 * usuarios en una base de datos
		 * auth.jdbcAuthentication().dataSource(dataSource)
        	.usersByUsernameQuery("select username, password, enabled"
            	+ " from users where username=?")
        	.authoritiesByUsernameQuery("select username, authority "
            	+ "from authorities where username=?");
*/
	}
	//definición de políticas de seguridad
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
		.authorizeRequests()
		//solo los miembros del rol admin podrán realizar altas
		//y para ver la lista de contactos, tendrán que estar autenticados
		.antMatchers("/login").permitAll()
		.antMatchers(HttpMethod.POST,"/contactos").hasRole("ADMIN")
		.antMatchers("/caja").hasAuthority("ADMIN")
		.antMatchers("/venta/**").authenticated()
		.antMatchers("/contactos").authenticated()
		//.antMatchers("/**").authenticated()
		//.antMatchers("/contactos/**").authenticated()
				.and()
				.csrf()
				.disable()
				.formLogin()
				.loginPage("/login")
				.failureUrl("/login?error=true")
				.defaultSuccessUrl("/home")
				.usernameParameter("user")
				.passwordParameter("password")
				.and()
					.httpBasic();
	
	}
}

