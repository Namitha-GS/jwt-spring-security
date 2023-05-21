package com.namitha.jwt.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.namitha.jwt.service.JwtService;
import com.namitha.jwt.service.MyUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {
	
	@Autowired JwtService jwtService;
	
	@Autowired MyUserDetailsService myUserDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		/*
		 * authHeader contains data from Authorization tab
		 * Incoming token=Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiaWF0IjoxNjg0NjgyODA5LCJleHAiOjE2ODQ2ODQ2MDl9
		 *                                              .kO6nwqfmQ6zybrCQDoTAJjt3i14Pg6NfO1deUXji4eo
		 * Exclude "Bearer " from incoming token, after excluding - we will get correct token
		 * We can extract username from this correct token
		 * SecurityContextHolder.getContext().getAuthentication() -> indicates current logged-in user
		 * so if there is no current logged-in user, then it will be null,
		 * so if it is valid token, then set token to SecurityContextHolder.getContext()
		 */
		String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            username = jwtService.extractUsername(token);
        }
        
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
        	UserDetails userDtls = myUserDetailsService.loadUserByUsername(username);
        	if(jwtService.validateToken(token, userDtls)) {
        		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDtls, null, userDtls.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
        	}
        }
        /*
         * after JwtAuthFilter execution, continue executing other filters i.e.,filter chaining,
         * filterChain.doFilter(request,response)
         */
        filterChain.doFilter(request, response);	
	}

}
