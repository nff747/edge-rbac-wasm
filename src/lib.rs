pub mod bitflags;
pub mod resource;
pub mod abac;
pub mod graph;
pub mod policy;
pub mod cache;
pub mod audit;
pub mod tenant;
pub mod compiler;
pub mod validator;
pub mod wasm;
pub mod engine;

// Re-exports
pub use bitflags::*;
pub use resource::ResourcePattern;
pub use abac::{AttributeCondition, Operator};
pub use graph::RoleGraph;
pub use policy::{Effect, PolicyDocument, PolicyRule};
pub use cache::DecisionCache;
pub use audit::AuditLogEntry;
pub use tenant::TenantHierarchy;
pub use compiler::PolicyBinaryCodec;
pub use wasm::WasmEdgeRbac;
pub use engine::UnifiedEngine;
