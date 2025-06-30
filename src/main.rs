use actix_web::{web, App, HttpResponse, HttpServer, Result as ActixResult, middleware::Logger};
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::AccountMeta,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_token::instruction as token_instruction;
use std::{env, str::FromStr};
use base64::{Engine as _, engine::general_purpose};

// Response structures
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(error: String) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

// Request/Response DTOs
#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

// Add new response struct for send_sol
#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

// Add new response structs for send_token
#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<TokenAccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenAccountInfo {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

// Helper function to convert AccountMeta to AccountInfo
fn account_meta_to_info(meta: &AccountMeta) -> AccountInfo {
    AccountInfo {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }
}

// Add helper function for send_token
fn account_meta_to_token_info(meta: &AccountMeta) -> TokenAccountInfo {
    TokenAccountInfo {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
    }
}

// Endpoint handlers
async fn generate_keypair() -> ActixResult<HttpResponse> {
    let keypair = Keypair::new();
    let response = KeypairResponse {
        pubkey: keypair.pubkey().to_string(),
        secret: bs58::encode(keypair.to_bytes()).into_string(),
    };
    
    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn create_token(req: web::Json<CreateTokenRequest>) -> ActixResult<HttpResponse> {
    // Validate required fields are not empty
    if req.mint_authority.is_empty() || req.mint.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Missing required fields".to_string())));
    }

    // Parse the addresses
    let mint_authority = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid mint authority".to_string()))),
    };
    
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid mint address".to_string()))),
    };

    // Create the initialize mint instruction
    let instruction = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        req.decimals,
    ).unwrap();

    let accounts: Vec<AccountInfo> = instruction.accounts.iter()
        .map(account_meta_to_info)
        .collect();

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn mint_token(req: web::Json<MintTokenRequest>) -> ActixResult<HttpResponse> {
    // Validate required fields are not empty
    if req.mint.is_empty() || req.destination.is_empty() || req.authority.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Missing required fields".to_string())));
    }

    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid mint address".to_string()))),
    };
    
    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid destination address".to_string()))),
    };
    
    let authority = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid authority address".to_string()))),
    };

    // Create mint to instruction
    let instruction = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    ).unwrap();

    let accounts: Vec<AccountInfo> = instruction.accounts.iter()
        .map(account_meta_to_info)
        .collect();

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn sign_message(req: web::Json<SignMessageRequest>) -> ActixResult<HttpResponse> {
    // Validate required fields are not empty
    if req.message.is_empty() || req.secret.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Missing required fields".to_string())));
    }

    // Decode the secret key
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid secret key".to_string()))),
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid secret key format".to_string()))),
    };

    // Sign the message
    let message_bytes = req.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    let response = SignMessageResponse {
        signature: general_purpose::STANDARD.encode(signature.as_ref()),
        public_key: keypair.pubkey().to_string(),
        message: req.message.clone(),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn verify_message(req: web::Json<VerifyMessageRequest>) -> ActixResult<HttpResponse> {
    // Validate required fields are not empty
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Missing required fields".to_string())));
    }

    // Parse public key (base58-encoded)
    let pubkey = match Pubkey::from_str(&req.pubkey) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid public key".to_string()))),
    };

    // Decode signature (base64-encoded)
    let signature_bytes = match general_purpose::STANDARD.decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid signature".to_string()))),
    };

    // Check signature length (should be 64 bytes for Ed25519)
    if signature_bytes.len() != 64 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid signature format".to_string())));
    }

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid signature format".to_string()))),
    };

    // Verify the signature - use the correct method
    let message_bytes = req.message.as_bytes();
    let is_valid = signature.verify(&pubkey.to_bytes(), message_bytes);

    let response = VerifyMessageResponse {
        valid: is_valid,
        message: req.message.clone(),
        pubkey: req.pubkey.clone(),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn send_sol(req: web::Json<SendSolRequest>) -> ActixResult<HttpResponse> {
    // Validate required fields are not empty
    if req.from.is_empty() || req.to.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Missing required fields".to_string())));
    }

    let from = match Pubkey::from_str(&req.from) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid from address".to_string()))),
    };
    
    let to = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid to address".to_string()))),
    };

    if req.lamports == 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Amount must be greater than 0".to_string())));
    }

    // Create transfer instruction
    let instruction = system_instruction::transfer(&from, &to, req.lamports);

    // Convert accounts to just addresses (strings)
    let accounts: Vec<String> = instruction.accounts.iter()
        .map(|meta| meta.pubkey.to_string())
        .collect();

    let response = SendSolResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

async fn send_token(req: web::Json<SendTokenRequest>) -> ActixResult<HttpResponse> {
    // Validate required fields are not empty
    if req.destination.is_empty() || req.mint.is_empty() || req.owner.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Missing required fields".to_string())));
    }

    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid destination address".to_string()))),
    };
    
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid mint address".to_string()))),
    };
    
    let owner = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid owner address".to_string()))),
    };

    if req.amount == 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error("Amount must be greater than 0".to_string())));
    }

    // For this example, we'll assume source is the owner's associated token account
    let source = spl_associated_token_account::get_associated_token_address(&owner, &mint);

    let instruction = token_instruction::transfer(
        &spl_token::id(),
        &source,
        &destination,
        &owner,
        &[],
        req.amount,
    ).unwrap();

    let accounts: Vec<TokenAccountInfo> = instruction.accounts.iter()
        .map(account_meta_to_token_info)
        .collect();

    let response = SendTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

// Fix: Remove async and make it synchronous
fn json_error_handler(err: actix_web::error::JsonPayloadError, _req: &actix_web::HttpRequest) -> actix_web::error::Error {
    let resp = HttpResponse::BadRequest().json(ApiResponse::<()>::error("Missing required fields".to_string()));
    actix_web::error::InternalError::from_response(err, resp).into()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();
    
    let port = env::var("PORT").unwrap_or("8080".to_string());
    let bind_address = format!("0.0.0.0:{}", port);
    
    println!("🚀 Solana HTTP Server starting at http://{}", bind_address);
    
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .app_data(
                web::JsonConfig::default()
                    .limit(4096)
                    .error_handler(json_error_handler)
            )
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind(&bind_address)?
    .run()
    .await
}
