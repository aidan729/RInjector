use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    pub dll_paths: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            dll_paths: Vec::new(),
        }
    }
}

impl Config {
    fn config_path() -> PathBuf {
        // Store config in the same directory as the executable
        let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
        let exe_dir = exe_path.parent().unwrap_or_else(|| std::path::Path::new("."));
        exe_dir.join("injector_config.json")
    }

    pub fn load() -> Self {
        let path = Self::config_path();

        if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => {
                    match serde_json::from_str(&content) {
                        Ok(config) => {
                            println!("Loaded config from: {:?}", path);
                            return config;
                        }
                        Err(e) => {
                            eprintln!("Failed to parse config: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read config: {}", e);
                }
            }
        }

        Config::default()
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        let path = Self::config_path();
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        println!("Saved config to: {:?}", path);
        Ok(())
    }

    pub fn add_dll(&mut self, path: String) {
        if !self.dll_paths.contains(&path) {
            self.dll_paths.push(path);
            let _ = self.save();
        }
    }

    pub fn remove_dll(&mut self, path: &str) {
        self.dll_paths.retain(|p| p != path);
        let _ = self.save();
    }

    pub fn clear_dlls(&mut self) {
        self.dll_paths.clear();
        let _ = self.save();
    }
}
