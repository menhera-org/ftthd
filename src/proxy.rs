
use std::collections::HashSet;

pub struct ProxyInstance {
    upstream_if_name: String,
    downstream_if_names: HashSet<String>,
}

impl ProxyInstance {
    pub fn new(upstream_if_name: &str, downstream_if_names: &[&str]) -> Self {
        let downstream_if_names = downstream_if_names.iter().map(|s| s.to_string()).collect();
        Self {
            upstream_if_name: upstream_if_name.to_string(),
            downstream_if_names,
        }
    }

    pub fn upstream_if_name(&self) -> &str {
        &self.upstream_if_name
    }

    pub fn downstream_if_names(&self) -> &HashSet<String> {
        &self.downstream_if_names
    }
}
