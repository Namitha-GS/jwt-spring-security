package com.namitha.jwt.dto;

public class Product {
	
	private int productId;
	private String name;
	private double qty;
	private double price;
	
	public int getProductId() {
		return productId;
	}
	public void setProductId(int productId) {
		this.productId = productId;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public double getQty() {
		return qty;
	}
	public void setQty(double qty) {
		this.qty = qty;
	}
	public double getPrice() {
		return price;
	}
	public void setPrice(double price) {
		this.price = price;
	}
	
	@Override
	public String toString() {
		return "Product [productId=" + productId + ", name=" + name + ", qty=" + qty + ", price=" + price + "]";
	}
	
	public Product(int productId, String name, double qty, double price) {
		super();
		this.productId = productId;
		this.name = name;
		this.qty = qty;
		this.price = price;
	}
	
	public Product() {
		
	}

}
