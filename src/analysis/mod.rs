pub mod function_discovery;

// Note: FunctionDiscovery is generic over lifetime parameters so we don't re-export it
// Use analysis::function_discovery::FunctionDiscovery directly