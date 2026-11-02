use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use crate::scanner::{HostResult, NetworkInfo, NetworkScanner};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub network: Option<String>,
    pub scan_ports: Option<bool>,
    pub port_list: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResponse {
    pub scan_id: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub network_info: Option<NetworkInfo>,
    pub hosts: Vec<HostResult>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub message: String,
}

pub struct AppState {
    scanner: NetworkScanner,
    scans: Arc<RwLock<HashMap<String, ScanResult>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            scanner: NetworkScanner::new(),
            scans: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

pub fn create_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .route("/api/v1/network/info", get(get_network_info))
        .route("/api/v1/scan", post(start_scan))
        .route("/api/v1/scan/:scan_id", get(get_scan_status))
        .route("/api/v1/scan/:scan_id/results", get(get_scan_results))
        .route("/api/v1/scans", get(list_scans))
}

async fn root_handler() -> Json<HashMap<String, String>> {
    let mut response = HashMap::new();
    response.insert("name".to_string(), "Network Scanner API".to_string());
    response.insert("version".to_string(), "0.1.0".to_string());
    response.insert("status".to_string(), "running".to_string());
    response.insert("docs".to_string(), "/api/v1".to_string());
    Json(response)
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: Utc::now(),
        version: "0.1.0".to_string(),
    })
}

async fn get_network_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NetworkInfo>, (StatusCode, Json<ApiError>)> {
    match state.scanner.discover_network() {
        Ok(info) => Ok(Json(info)),
        Err(e) => {
            warn!("Failed to discover network: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: "NETWORK_DISCOVERY_FAILED".to_string(),
                    message: e.to_string(),
                }),
            ))
        }
    }
}

async fn start_scan(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, Json<ApiError>)> {
    let scan_id = Uuid::new_v4().to_string();
    let scan_result = ScanResult {
        scan_id: scan_id.clone(),
        status: "running".to_string(),
        created_at: Utc::now(),
        completed_at: None,
        network_info: None,
        hosts: Vec::new(),
        error: None,
    };

    // Store initial scan result
    {
        let mut scans = state.scans.write().await;
        scans.insert(scan_id.clone(), scan_result);
    }

    // Start scan in background
    let scanner = state.scanner.clone();
    let scans = state.scans.clone();
    let scan_id_clone = scan_id.clone();
    
    tokio::spawn(async move {
        info!("Starting background scan: {}", scan_id_clone);
        
        // Discover network
        let network_info = match scanner.discover_network() {
            Ok(info) => Some(info),
            Err(e) => {
                warn!("Failed to discover network: {}", e);
                let mut scans = scans.write().await;
                if let Some(scan) = scans.get_mut(&scan_id_clone) {
                    scan.status = "failed".to_string();
                    scan.error = Some(e.to_string());
                }
                return;
            }
        };

        // Determine network to scan
        let networks_to_scan = if let Some(network_str) = request.network {
            match network_str.parse::<IpNetwork>() {
                Ok(network) => vec![network],
                Err(e) => {
                    warn!("Invalid network: {}", e);
                    let mut scans = scans.write().await;
                    if let Some(scan) = scans.get_mut(&scan_id_clone) {
                        scan.status = "failed".to_string();
                        scan.error = Some(format!("Invalid network: {}", e));
                    }
                    return;
                }
            }
        } else {
            // Use networks from interfaces
            network_info.as_ref()
                .map(|info| info.interfaces.iter()
                    .map(|iface| iface.network)
                    .collect())
                .unwrap_or_default()
        };

        // Scan networks
        let mut all_hosts = Vec::new();
        for network in networks_to_scan {
            match scanner.scan_network(&network).await {
                Ok(hosts) => {
                    all_hosts.extend(hosts);
                }
                Err(e) => {
                    warn!("Failed to scan network {}: {}", network, e);
                }
            }
        }

        // Port scanning if requested
        if request.scan_ports.unwrap_or(false) {
            let ports = request.port_list.unwrap_or_else(|| vec![80, 443, 22, 8080]);
            for host in &all_hosts {
                if host.is_up {
                    if let Err(e) = scanner.scan_ports(host.ip, &ports).await {
                        warn!("Failed to scan ports on {}: {}", host.ip, e);
                    }
                }
            }
        }

        // Update scan result
        let host_count = all_hosts.len();
        let mut scans = scans.write().await;
        if let Some(scan) = scans.get_mut(&scan_id_clone) {
            scan.status = "completed".to_string();
            scan.completed_at = Some(Utc::now());
            scan.network_info = network_info;
            scan.hosts = all_hosts;
        }
        
        info!("Scan {} completed with {} hosts found", scan_id_clone, host_count);
    });

    Ok(Json(ScanResponse {
        scan_id,
        status: "running".to_string(),
        message: "Scan started successfully".to_string(),
    }))
}

async fn get_scan_status(
    State(state): State<Arc<AppState>>,
    Path(scan_id): Path<String>,
) -> Result<Json<ScanResult>, (StatusCode, Json<ApiError>)> {
    let scans = state.scans.read().await;
    match scans.get(&scan_id) {
        Some(result) => Ok(Json(result.clone())),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "SCAN_NOT_FOUND".to_string(),
                message: format!("Scan {} not found", scan_id),
            }),
        )),
    }
}

async fn get_scan_results(
    State(state): State<Arc<AppState>>,
    Path(scan_id): Path<String>,
) -> Result<Json<Vec<HostResult>>, (StatusCode, Json<ApiError>)> {
    let scans = state.scans.read().await;
    match scans.get(&scan_id) {
        Some(result) => {
            if result.status == "completed" {
                Ok(Json(result.hosts.clone()))
            } else {
                Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiError {
                        error: "SCAN_NOT_COMPLETE".to_string(),
                        message: format!("Scan {} is still {}", scan_id, result.status),
                    }),
                ))
            }
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "SCAN_NOT_FOUND".to_string(),
                message: format!("Scan {} not found", scan_id),
            }),
        )),
    }
}

async fn list_scans(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<ScanResult>> {
    let scans = state.scans.read().await;
    let results: Vec<ScanResult> = scans.values().cloned().collect();
    Json(results)
}

pub async fn run_server(port: u16) -> anyhow::Result<()> {
    let state = Arc::new(AppState::new());
    let app = create_router().with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Starting server on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
