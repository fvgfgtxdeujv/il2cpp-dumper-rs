use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Config {
    pub dump_method: bool,
    pub dump_field: bool,
    pub dump_property: bool,
    pub dump_attribute: bool,
    pub dump_method_offset: bool,
    pub dump_field_offset: bool,
    pub dump_type_def_index: bool,
    pub dump_assembly_name: bool,
    pub generate_struct: bool,
    pub generate_dummy_dll: bool,
    pub require_any_key: bool,
    pub dummy_dll_add_token: bool,
    pub force_il2cpp_version: bool,
    pub force_version: f64,
    pub force_dump: bool,
    pub no_redirected_pointer: bool,
    pub split_dump_per_type: bool,
    pub generate_generics_dump: bool,
    pub dump_generics_rgctx: bool,
    pub dump_generics_method_specs: bool,
    pub dump_generics_custom_attributes: bool,
    pub dump_generics_string_literals: bool,
    pub dump_generics_metadata_usages: bool,
    pub dump_generics_vtables: bool,
    pub dump_generics_interfaces: bool,
    pub dump_disassembly: bool,
    pub dump_disassembly_target: u8, // 0 = Both, 1 = Flat dump.cs, 2 = Split DiffableCs
    pub dump_disassembly_hex_bytes: bool,
    pub dump_disassembly_field_names: bool,
    pub dump_disassembly_annotations: bool,
    pub dump_disassembly_cfg: bool,
    pub max_disassembly_instructions: usize,
    pub generate_cpp_scaffold: bool,
    pub mangle_names: bool,
    pub enhanced_ida_metadata: bool,
    pub generate_unity_headers: bool,
    pub compiler_layout: String,
    pub use_topological_sort: bool,
    pub codm: bool,
    /// Thread-static fields, FieldRVA blobs, and `static_metadata.json` export.
    pub dump_static_field_metadata: bool,
    /// Include hex/metadata for FieldRVA (`PrivateImplementationDetails`) entries.
    pub dump_field_rva_data: bool,
    pub max_field_rva_dump_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dump_method: true,
            dump_field: true,
            dump_property: true,
            dump_attribute: true,
            dump_method_offset: true,
            dump_field_offset: true,
            dump_type_def_index: true,
            dump_assembly_name: true,
            generate_struct: true,
            generate_dummy_dll: true,
            require_any_key: true,
            dummy_dll_add_token: true,
            force_il2cpp_version: false,
            force_version: 24.3,
            force_dump: false,
            no_redirected_pointer: false,
            split_dump_per_type: true,
            generate_generics_dump: true,
            dump_generics_rgctx: true,
            dump_generics_method_specs: true,
            dump_generics_custom_attributes: true,
            dump_generics_string_literals: true,
            dump_generics_metadata_usages: true,
            dump_generics_vtables: true,
            dump_generics_interfaces: true,
            dump_disassembly: false,
            dump_disassembly_target: 0,
            dump_disassembly_hex_bytes: true,
            dump_disassembly_field_names: true,
            dump_disassembly_annotations: true,
            dump_disassembly_cfg: true,
            max_disassembly_instructions: 512,
            generate_cpp_scaffold: true,
            mangle_names: true,
            enhanced_ida_metadata: true,
            generate_unity_headers: true,
            compiler_layout: "GCC".to_string(),
            use_topological_sort: true,
            codm: false,
            dump_static_field_metadata: false,
            dump_field_rva_data: false,
            max_field_rva_dump_bytes: 4096,
        }
    }
}

impl Config {
    pub fn load_from_file(path: &str) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn save_to_file(&self, path: &str) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}
