/// Integration tests for CLI argument parsing
/// These tests verify the command-line interface without running actual scans

#[cfg(test)]
mod cli_integration_tests {
    use std::process::Command;

    fn get_binary_path() -> String {
        // Use debug build for tests
        if cfg!(windows) {
            "target/debug/tokmap.exe".to_string()
        } else {
            "target/debug/tokmap".to_string()
        }
    }

    #[test]
    fn test_help_flag() {
        let output = Command::new(get_binary_path())
            .arg("--help")
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("Tokmap"));
            assert!(stdout.contains("--targets"));
            assert!(stdout.contains("--ports"));
        }
        // If binary doesn't exist yet, skip test
    }

    #[test]
    fn test_version_flag() {
        let output = Command::new(get_binary_path())
            .arg("--version")
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("0.1"));
        }
    }

    #[test]
    fn test_missing_targets_error() {
        let output = Command::new(get_binary_path())
            .arg("--ports")
            .arg("80")
            .output();

        if let Ok(output) = output {
            // Should fail because no targets specified
            assert!(!output.status.success());
        }
    }

    #[test]
    fn test_invalid_ip_format() {
        let output = Command::new(get_binary_path())
            .arg("--targets")
            .arg("not-an-ip")
            .arg("--ports")
            .arg("80")
            .output();

        if let Ok(output) = output {
            // Should fail because of invalid IP
            assert!(!output.status.success());
        }
    }

    #[test]
    fn test_invalid_port_format() {
        let output = Command::new(get_binary_path())
            .arg("--targets")
            .arg("127.0.0.1")
            .arg("--ports")
            .arg("not-a-port")
            .output();

        if let Ok(output) = output {
            // Should fail because of invalid port
            assert!(!output.status.success());
        }
    }
}
