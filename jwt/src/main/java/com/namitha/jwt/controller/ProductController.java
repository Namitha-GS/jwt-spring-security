package com.namitha.jwt.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.namitha.jwt.dto.AuthRequest;
import com.namitha.jwt.dto.Product;
import com.namitha.jwt.service.JwtService;
import com.namitha.jwt.service.ProductService;

@RestController
@RequestMapping("/products")
public class ProductController {
	
	@Autowired ProductService service;
	
	@Autowired AuthenticationManager authenticationManager;
	
	@Autowired JwtService jwtService;
	
	/*
	 * localhost:8080/products/
	 * No Authentication (GET)
	 */
	@GetMapping("/")
	public String home() {
		return "Welcome to Products";
	}
	
	
	/*
	 * localhost:8080/products/authenticate
	 * No Authentication, this generates Token (POST)
	 */
	@PostMapping("/authenticate")
    public String authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        if (authentication.isAuthenticated()) {
            return jwtService.generateToken(authRequest.getUsername());
        } else {
            throw new UsernameNotFoundException("invalid user request !");
        }
    }
	
	
	/*
	 * localhost:8080/products/all
	 * Authentication required, so pass the above obtained token as Bearer token (GET)
	 */
	@GetMapping("/all")
	public List<Product> getAllProducts() {
		return service.getAllMessages();
	}
	
	
	/*
	 * localhost:8080/products/3
	 * Authentication required, so pass the above obtained token as Bearer token (GET)
	 */
	@GetMapping("/{id}")
	public Product getAllProducts(@PathVariable("id") int productId) {
		return service.getProduct(productId);
	}

}
