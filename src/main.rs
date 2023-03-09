use aes_gcm_siv::aead::rand_core::RngCore;
use aes_gcm_siv::aead::AeadInPlace;
use aes_gcm_siv::Error as AesError;
use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv, Nonce,
};
use argparse::{ArgumentParser, Store, StoreTrue};
use base64::{alphabet, engine, Engine as _};
use enum_display::EnumDisplay;
use rand::distributions::Alphanumeric;
use rand::Rng;
use sha3::{Digest, Sha3_256};
use std::fmt::Display;
use std::fs::File;
use std::io::Error as IoError;
use std::io::{BufReader, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Instant;
use std::{fmt, io};

const BASE_64_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";

fn write_file(out_file: &Path, data: Vec<u8>) {
    let mut file = File::create(out_file.to_str().unwrap()).expect("cannot open file!");
    file.write_all(data.as_slice())
        .expect("TODO: panic message");
}

enum InfoMode {
    Encrypt,
    Decrypt,
    Error,
}
struct EncryptionInfo {
    mode: InfoMode,
    in_file_name: String,
    out_file_name: String,
    message: String,
    time_secs: f32,
    bandwidth_mbps: f32,
}

impl EncryptionInfo {
    fn as_encryption_success(
        in_file_name: String,
        out_file_name: String,
        time_secs: f32,
        bandwidth_mbps: f32,
    ) -> EncryptionInfo {
        return EncryptionInfo {
            mode: InfoMode::Encrypt,
            in_file_name,
            out_file_name,
            message: String::from(""),
            time_secs,
            bandwidth_mbps,
        };
    }
    fn as_decryption_success(
        in_file_name: String,
        out_file_name: String,
        time_secs: f32,
        bandwidth_mbps: f32,
    ) -> EncryptionInfo {
        return EncryptionInfo {
            mode: InfoMode::Decrypt,
            in_file_name,
            out_file_name,
            message: String::from(""),
            time_secs,
            bandwidth_mbps,
        };
    }
    fn as_error(in_file_name: String, message: String) -> EncryptionInfo {
        return EncryptionInfo {
            mode: InfoMode::Error,
            in_file_name,
            out_file_name: String::from(""),
            message,
            time_secs: 0.0,
            bandwidth_mbps: 0.0,
        };
    }
}

impl Display for EncryptionInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.mode {
            InfoMode::Encrypt => {
                write!(
                    f,
                    "🔐 {} => {} (🕗{:.2} s, 💨{:.2} mb/s)",
                    self.in_file_name, self.out_file_name, self.time_secs, self.bandwidth_mbps
                )
            }
            InfoMode::Decrypt => {
                write!(
                    f,
                    "🔓 {} => {} (🕗{:.2} s, 💨{:.2} mb/s)",
                    self.in_file_name, self.out_file_name, self.time_secs, self.bandwidth_mbps
                )
            }
            InfoMode::Error => {
                write!(f, "❌ {} : {}", self.message, self.in_file_name)
            }
        }
    }
}

fn encrypt_file_to_dir(
    input_file_path: &Path,
    output_directory: &Path,
    encryption_password: &String,
) -> EncryptionInfo {
    // TODO check if file exists before encryption, ask user to re-encrypt
    let t0 = Instant::now();

    // generating salt
    let salt_str: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(12) // 96 bits salt
        .map(char::from)
        .collect();

    // generate password (with salt) hash which is used to encrypt file
    let mut hasher = Sha3_256::new();
    let password_seed = format!("{}{}", &salt_str, &encryption_password);
    hasher.update(password_seed);
    let password_hash = hasher.finalize();

    // generating nonce
    let mut nonce_value = [0; 12];
    OsRng.fill_bytes(&mut nonce_value); // 96-bits; unique per message
    let nonce = Nonce::from_slice(&nonce_value);

    // generate cipher
    let cipher = Aes256GcmSiv::new_from_slice(password_hash.as_slice()).unwrap();

    // read file
    let file_name = Path::new(input_file_path)
        .file_name()
        .expect("Error")
        .to_str()
        .unwrap();
    let mut plaintext = get_file_data(&input_file_path);
    let original_file_size = plaintext.len();

    // encrypt data in place
    cipher
        .encrypt_in_place(nonce, b"asdf", &mut plaintext)
        .expect("error2");
    let ciphertext_data = plaintext;

    // encrypt file name
    let ciphertext_file_name = cipher.encrypt(nonce, file_name.as_bytes()).expect("error");

    // base64 encode salt, nonce and filename
    // base64 alphabet but replaced '/' with '-'
    let alphabet = alphabet::Alphabet::new(BASE_64_ALPHABET).unwrap();
    let base64engine_custom =
        engine::GeneralPurpose::new(&alphabet, engine::GeneralPurposeConfig::new());

    let encoded_salt: String = base64engine_custom.encode(salt_str);
    let encoded_nonce: String = base64engine_custom.encode(nonce);
    let encoded_file_name: String = base64engine_custom.encode(ciphertext_file_name);

    // generate filename of encrypted file
    let encrypted_out_file_name: String = format!(
        "{}_{}_{}",
        &encoded_salt, &encoded_nonce, &encoded_file_name
    );
    let out_path = output_directory.join(Path::new(encrypted_out_file_name.as_str()));
    write_file(out_path.as_path(), ciphertext_data);

    // get statistics
    let file_size_mb: f32 = (original_file_size / (1024 * 1024)) as f32;
    let encryption_time = t0.elapsed();
    let bandwidth_enc_mb_s: f32 = file_size_mb / encryption_time.as_secs_f32();

    EncryptionInfo::as_encryption_success(
        String::from(input_file_path.file_name().unwrap().to_str().unwrap()),
        String::from(out_path.file_name().unwrap().to_str().unwrap()),
        encryption_time.as_secs_f32(),
        bandwidth_enc_mb_s,
    )
}

fn decrypt_file_name(
    encrypted_name: &String,
    encryption_password: &String,
) -> Result<String, IoError> {
    let split: Vec<&str> = encrypted_name.split("_").collect();
    if split.len() != 3 {
        return Err(IoError::new(ErrorKind::InvalidData, "aiaiai"));
    }

    // base64 decode salt, nonce and filename
    // base64 alphabet but replaced '/' with '-'
    let alphabet = alphabet::Alphabet::new(BASE_64_ALPHABET).unwrap();
    let base64engine_custom =
        engine::GeneralPurpose::new(&alphabet, engine::GeneralPurposeConfig::new());

    // decode file name components
    let decoded_salt: Vec<u8> = base64engine_custom.decode(split[0]).expect("a");
    let decoded_nonce: Vec<u8> = base64engine_custom.decode(split[1]).expect("b");
    let decoded_file_name: Vec<u8> = match base64engine_custom.decode(split[2]) {
        Ok(x) => x,
        Err(_) => return Err(IoError::new(ErrorKind::InvalidData, "aiaiai")),
    };
    let salt_str = String::from_utf8(decoded_salt).unwrap();
    let nonce = Nonce::from_slice(&decoded_nonce);

    // generate password (with salt) hash which is used to encrypt file
    let mut hasher = Sha3_256::new();
    let password_seed = format!("{}{}", &salt_str, &encryption_password);
    hasher.update(password_seed);
    let password_hash = hasher.finalize();

    // generate cipher
    let cipher = Aes256GcmSiv::new_from_slice(password_hash.as_slice()).unwrap();

    let plaintext_decrypted = cipher.decrypt(nonce, decoded_file_name.as_ref());

    return match plaintext_decrypted {
        Ok(x) => Ok(String::from_utf8(x).unwrap()),
        Err(_) => Err(IoError::new(
            ErrorKind::PermissionDenied,
            "Invalid Password",
        )),
    };
}

fn decrypt_file_to_dir(
    input_file_path: &Path,
    output_directory: &Path,
    encryption_password: &String,
) -> EncryptionInfo {
    // TODO check if file exists before decryption ask user to proceed if so add (n) to decrypted file name
    let t0 = Instant::now();

    let file_name = input_file_path.file_name().unwrap().to_str().unwrap();
    let split: Vec<&str> = file_name.split("_").collect();

    // base64 decode salt, nonce and filename
    // base64 alphabet but replaced '/' with '-'
    let alphabet = alphabet::Alphabet::new(BASE_64_ALPHABET).unwrap();
    let base64engine_custom =
        engine::GeneralPurpose::new(&alphabet, engine::GeneralPurposeConfig::new());

    if split.len() != 3 {
        return EncryptionInfo::as_error(
            String::from(input_file_path.to_str().unwrap()),
            String::from("Invalid input file provided"),
        );
    }
    // decode file name components
    let decoded_salt = base64engine_custom.decode(split[0]).unwrap();
    let decoded_nonce = base64engine_custom.decode(split[1]).unwrap();
    let decoded_file_name = base64engine_custom.decode(split[2]).unwrap();

    let salt_str = String::from_utf8(decoded_salt).unwrap();
    let nonce = Nonce::from_slice(&decoded_nonce);

    // generate password (with salt) hash which is used to encrypt file
    let mut hasher = Sha3_256::new();
    let password_seed = format!("{}{}", &salt_str, &encryption_password);
    hasher.update(password_seed);
    let password_hash = hasher.finalize();

    // generate cipher
    let cipher = Aes256GcmSiv::new_from_slice(password_hash.as_slice()).unwrap();

    // read file
    let mut cipher_text = get_file_data(&input_file_path);
    let original_file_size = cipher_text.len();

    // decrypt file name
    let plaintext_decrypted_file_name = match cipher.decrypt(nonce, decoded_file_name.as_ref()) {
        Ok(x) => x,
        Err(e) => {
            if e == AesError {
                return EncryptionInfo::as_error(
                    String::from(input_file_path.to_str().unwrap()),
                    String::from("Invalid password"),
                );
            } else {
                panic!("Unexpected Error encountered {}", e);
            }
        }
    };

    // encrypt data in place
    cipher
        .decrypt_in_place(nonce, b"asdf", &mut cipher_text)
        .expect("Could not decrypt file!");
    let plaintext_data = cipher_text;

    let decrypted_file_name = String::from_utf8(plaintext_decrypted_file_name).unwrap();

    let out_path = output_directory.join(Path::new(decrypted_file_name.as_str()));
    write_file(out_path.as_path(), plaintext_data);

    // get statistics
    let file_size_mb: f32 = (original_file_size / (1024 * 1024)) as f32;
    let decryption_time = t0.elapsed();
    let bandwidth_enc_mb_s: f32 = file_size_mb / decryption_time.as_secs_f32();

    EncryptionInfo::as_decryption_success(
        String::from(input_file_path.file_name().unwrap().to_str().unwrap()),
        String::from(out_path.file_name().unwrap().to_str().unwrap()),
        decryption_time.as_secs_f32(),
        bandwidth_enc_mb_s,
    )
}

fn get_file_data(file_name: &Path) -> Vec<u8> {
    let file = File::open(file_name).expect("cannot open file");
    let mut buf_reader = BufReader::new(file);
    let mut buffer = Vec::new();
    let _count = buf_reader
        .read_to_end(&mut buffer)
        .expect("Could not read file correctly");
    return buffer;
}

#[derive(EnumDisplay, PartialEq)]
enum ApplicationMode {
    Encrypt,
    Decrypt,
}

impl FromStr for ApplicationMode {
    type Err = ();

    fn from_str(input: &str) -> Result<ApplicationMode, Self::Err> {
        if input.eq_ignore_ascii_case("D") || input.eq_ignore_ascii_case("decrypt") {
            return Ok(ApplicationMode::Decrypt);
        } else if input.eq_ignore_ascii_case("E") || input.eq_ignore_ascii_case("encrypt") {
            return Ok(ApplicationMode::Encrypt);
        }
        return Err(());
    }
}

fn main() {
    // retrieving arguments
    let mut mode_string: String = String::new();
    let mut input_path_string: String = String::new();
    let mut output_path_string: String = String::new();
    let mut whole_dir: bool = false;

    {
        // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description(
            "🔑 Simple Encryptor v1.0.1 🔑 \
            Encrypts/Decrypts files/directories based on user provided password with AES256 \
        (Aes256GcmSiv, encryption key is derived from password + 96bit random salt with SHA3)\
        ",
        );
        ap.refer(&mut mode_string).add_argument(
            "Mode",
            Store,
            "can be one of {D decrypt E encrypt}",
        );
        ap.refer(&mut input_path_string).add_argument(
            "Input path",
            Store,
            "file or directory to de/encrypt from",
        );
        ap.refer(&mut output_path_string).add_argument(
            "Output path",
            Store,
            "directory to de/encrypt to",
        );
        ap.refer(&mut whole_dir).add_option(
            &["-a", "--all"],
            StoreTrue,
            "de/encrypt all files in Directory",
        );

        ap.parse_args_or_exit();
    }

    // query user for information if no args provided
    while mode_string.len() == 0 {
        print!("❔ Enter Mode (D/decryption/E/encryption): ");
        io::stdout().flush().expect("Could not flush output buffer");
        io::stdin()
            .read_line(&mut mode_string)
            .expect("Failed to read line");
        // try to parse user input, else query again
        let temp_mode = ApplicationMode::from_str(mode_string.trim());
        if temp_mode.is_err() {
            eprintln!("❌ Invalid mode provided!");
            mode_string = String::new();
        }
    }
    while input_path_string.len() == 0 {
        print!("📂 Enter Path to Input file or Directory: ");
        io::stdout().flush().expect("Could not flush output buffer");
        io::stdin()
            .read_line(&mut input_path_string)
            .expect("Failed to read line");
        let temp_path = Path::new(input_path_string.trim());
        if !temp_path.exists() {
            println!("❌ Input directory not exist");
            input_path_string = String::new();
        }
    }

    while output_path_string.len() == 0 {
        print!("📁 Enter Path to Output file or Directory: ");
        io::stdout().flush().expect("Could not flush output buffer");
        io::stdin()
            .read_line(&mut output_path_string)
            .expect("Failed to read line");
        let temp_path = Path::new(output_path_string.trim());
        if !temp_path.exists() {
            println!("❌ Output directory not exist");
            output_path_string = String::new();
        }
    }

    // parse user input to enum / path object
    let mode: ApplicationMode = match ApplicationMode::from_str(mode_string.trim()) {
        Ok(x) => x,
        Err(_) => {
            eprintln!("❌ Invalid mode provided! ({})", mode_string);
            return;
        }
    };
    let input_path = Path::new(input_path_string.trim());
    if !input_path.exists() {
        eprintln!(
            "❌ Input path does not exist! ({})",
            input_path.to_str().unwrap()
        );
        return;
    }
    let output_path = Path::new(output_path_string.trim());
    if !output_path.exists() {
        eprintln!(
            "❌ Output directory does not exist! ({})",
            output_path.to_str().unwrap()
        );
        return;
    }
    if !output_path.is_dir() {
        eprintln!(
            "❌ Output path is not a directory ({})",
            output_path.to_str().unwrap()
        );
        return;
    }

    let password = get_password(&mode);

    match mode {
        ApplicationMode::Encrypt => {
            encrypt(input_path, output_path, &password, whole_dir);
        }
        ApplicationMode::Decrypt => {
            decrypt(input_path, output_path, &password, whole_dir);
        }
    }
}

fn get_password(mode: &ApplicationMode) -> String {
    let mut read_pass = false;
    let mut password = String::new();
    while !read_pass {
        print!("🔑 Enter Password: ");
        io::stdout().flush().expect("Could not flush output buffer");
        password = match rpassword::read_password() {
            Ok(x) => {
                read_pass = true;
                if &ApplicationMode::Encrypt == mode {
                    read_pass = validate_password(&x);
                }
                x
            }
            Err(_) => {
                eprintln!("❌ Password must only contain ASCII characters Try again!");
                continue;
            }
        };
    }

    return password;
}

fn validate_password(pass: &String) -> bool {
    print!("🔑 Repeat Password: ");
    io::stdout().flush().expect("Could not flush output buffer");
    let password_validation = match rpassword::read_password() {
        Ok(x) => x,
        Err(_) => {
            println!("❌ Passwords to not match! Try again!");
            return false;
        }
    };
    return if &password_validation == pass {
        true
    } else {
        println!("❌ Passwords to not match! Try again!");
        false
    };
}

fn encrypt(input_path: &Path, output_path: &Path, encryption_password: &String, all: bool) {
    if input_path.is_dir() {
        // if all flag is set encrypt all files in directory
        if all {
            for entry in input_path.read_dir().expect("read_dir call failed") {
                if let Ok(entry) = entry {
                    if entry.path().is_file() {
                        let info = encrypt_file_to_dir(
                            &entry.path().as_path(),
                            &output_path,
                            &encryption_password,
                        );
                        println!("{}", info);
                    }
                }
            }
        } else {
            // if flag is not set, let user choose file to process
            let selected_file = get_selection_from_dir(&input_path);
            let info = encrypt_file_to_dir(&selected_file, &output_path, &encryption_password);
            println!("{}", info);
        }
    } else {
        // user provided file as command line parameters
        let info = encrypt_file_to_dir(&input_path, &output_path, &encryption_password);
        println!("{}", info);
    }
}

fn decrypt(input_path: &Path, output_path: &Path, encryption_password: &String, all: bool) {
    if input_path.is_dir() {
        // if all flag is set decrypt all files in directory
        if all {
            for entry in input_path.read_dir().expect("read_dir call failed") {
                if let Ok(entry) = entry {
                    if entry.path().is_file() {
                        let info = decrypt_file_to_dir(
                            &entry.path().as_path(),
                            &output_path,
                            &encryption_password,
                        );
                        println!("{}", info);
                    }
                }
            }
        } else {
            // if flag is not set, let user choose file to process
            let selected_file = get_selection_from_encrypted_dir(&input_path, &encryption_password);
            match selected_file {
                Ok(f) => {
                    let info = decrypt_file_to_dir(&f, &output_path, &encryption_password);
                    println!("{}", info);
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    println!("{}", e)
                }
                Err(e) => panic!("{}", e),
            }
        }
    } else {
        // user provided file as command line parameters
        let info = decrypt_file_to_dir(&input_path, &output_path, &encryption_password);
        println!("{}", info);
    }
}

fn get_selection_from_dir(directory: &Path) -> PathBuf {
    let paths: Vec<PathBuf> = match directory.read_dir() {
        Err(e) if e.kind() == ErrorKind::NotFound => Vec::new(),
        Err(_) => Vec::new(),
        Ok(entries) => entries.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
    };

    return get_selection(paths);
}

fn get_selection_from_encrypted_dir(
    directory: &Path,
    password: &String,
) -> Result<PathBuf, IoError> {
    let paths: Vec<String> = match directory.read_dir() {
        Err(e) if e.kind() == ErrorKind::NotFound => Vec::new(),
        Err(_) => Vec::new(),
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| String::from(e.path().to_str().unwrap()))
            .collect(),
    };

    let decrypted_file_names = decrypt_file_names(&paths, password);

    if !decrypted_file_names.is_empty() {
        println!("📂 Found files:");
        for i in decrypted_file_names.iter().enumerate() {
            println!(" {}: {} ({})", i.0, i.1 .1, i.1 .0);
        }
    } else {
        return Err(IoError::new(
            ErrorKind::NotFound,
            "⚠️ No encrypted files found for given password!",
        ));
    }

    let selection_index: usize = get_selection_index(decrypted_file_names.len());

    let p = PathBuf::from(&decrypted_file_names[selection_index].0);
    let p = directory.join(p);

    return if p.exists() {
        Ok(p)
    } else {
        Err(IoError::new(
            ErrorKind::NotFound,
            format!(
                "❌ File does not exist but should! ({})",
                p.file_name().unwrap().to_str().unwrap()
            ),
        ))
    };
}

fn get_selection_index(len: usize) -> usize {
    let mut selection_index: usize = 0;
    let mut selected_file = false;
    while !selected_file {
        print!("☝️ Enter number of file you want to process: ");
        io::stdout().flush().expect("Could not flush output buffer");
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");
        selection_index = match input.trim().parse() {
            Ok(num) => {
                selected_file = true;
                num
            }
            Err(_) => {
                eprintln!("❌ Invalid number!");
                continue;
            }
        };
        if selection_index >= len {
            eprintln!("❌ Invalid file index!");
            selected_file = false;
        }
    }
    selection_index
}

fn get_selection(paths: Vec<PathBuf>) -> PathBuf {
    println!("📂 Found files:");
    for i in paths.iter().enumerate() {
        println!(
            " {}: {}",
            i.0,
            i.1.as_path().file_name().unwrap().to_str().unwrap()
        );
    }

    let selection_index: usize = get_selection_index(paths.len());
    return paths[selection_index].clone();
}

fn decrypt_file_names(
    encrypted_names: &Vec<String>,
    encryption_password: &String,
) -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = Vec::new();
    for n in encrypted_names {
        let file_name: String = Path::new(&n)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();

        let decrypted_name: String = match decrypt_file_name(&file_name, &encryption_password) {
            Ok(x) => x,
            Err(_) => continue,
        };
        files.push((file_name, decrypted_name));
    }
    return files;
}
