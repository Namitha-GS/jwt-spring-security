package com.namitha.jwt.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

import com.namitha.jwt.dto.Product;

@Service
public class ProductService {
	
	List<Product> list = null;
	public List<Product> list(){
		Product p1 = new Product(1, "Cream", 1, 10);
		Product p2 = new Product(2, "Soap", 3, 30);
		Product p3 = new Product(3, "Shampoo", 1, 250);	
		list = new ArrayList<>();
		list.add(p1);
		list.add(p2);
		list.add(p3);
		return list;
	}
	
	public List<Product> getAllMessages() {		
		return list();
	}
	
	public Product getProduct(int id) {
		List<Product> listProduct = list();
		Product prod = listProduct.stream()
				.filter(product -> product.getProductId() == id)
				.findAny().orElse(new Product());
		return prod;
	}

}
