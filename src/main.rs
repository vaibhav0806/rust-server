use actix_web::{web, App, HttpResponse, HttpServer, Result};
use dotenv::dotenv;
use std::env;

async fn hello() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().body("Hello, World from Actix-web!"))
}

async fn greet(path: web::Path<String>) -> Result<HttpResponse> {
    let name = path.into_inner();
    Ok(HttpResponse::Ok().body(format!("Hello, {}!", name)))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    
    let port = env::var("PORT").unwrap_or("8080".to_string());
    let bind_address = format!("127.0.0.1:{}", port);
    
    println!("Starting server at http://{}", bind_address);
    
    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(hello))
            .route("/hello/{name}", web::get().to(greet))
    })
    .bind(&bind_address)?
    .run()
    .await
}
