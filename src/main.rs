use std::fs::File;
use std::io::{Read, Write};

pub fn main() {
    // assert /dev/attestation/quote exists

    if !std::path::Path::new("/dev/attestation/quote").exists() {
        eprintln!("Cannot find `/dev/attestation/quote`; are you running under SGX, with remote attestation enabled?");
        std::process::exit(1);
    }

    if let Ok(mut attestation_type_file) = File::open("/dev/attestation/attestation_type") {
        let mut attestation_type = String::new();
        if let Ok(_) = attestation_type_file.read_to_string(&mut attestation_type) {
            println!("Detected attestation type: {}", attestation_type.trim());
        }
    }

    if let Ok(mut user_report_data_file) = File::create("/dev/attestation/user_report_data") {
        let zeros = vec![0u8; 64];
        if let Ok(_) = user_report_data_file.write_all(&zeros) {
            println!("Successfully wrote zeros to user_report_data");
        }
    }

    if let Ok(mut quote_file) = File::open("/dev/attestation/quote") {
        let mut quote = Vec::new();
        if let Ok(_) = quote_file.read_to_end(&mut quote) {
            println!(
                "Extracted SGX quote with size = {} and the following fields:",
                quote.len()
            );
            println!("quote: {}", hex::encode(&quote));
            println!(
                "  ATTRIBUTES.FLAGS: {}  [ Debug bit: {} ]",
                hex::encode(&quote[96..104]),
                quote[96] & 2 > 0
            );
            println!("  ATTRIBUTES.XFRM:  {}", hex::encode(&quote[104..112]));
            // MRENCLAVE is a 256-bit value that represents the hash (message digest) of the code and data within an enclave. It is a critical security feature of SGX and provides integrity protection for the enclave's contents. When an enclave is instantiated, its MRENCLAVE value is computed and stored in the SGX quote. This value can be used to ensure that the enclave being run is the intended and correct version.
            println!("  MRENCLAVE:        {}", hex::encode(&quote[112..144]));
            // MRSIGNER is a 256-bit value that identifies the entity or signer responsible for signing the enclave code. It represents the microcode revision of the software entity that created the enclave. Each entity or signer, such as a software vendor or developer, has a unique MRSIGNER value associated with their signed enclaves. The MRSIGNER value provides a way to differentiate between different signers or entities, allowing applications to make trust decisions based on the signer's identity and trustworthiness.
            println!("  MRSIGNER:         {}", hex::encode(&quote[176..208]));
            println!("  ISVPRODID:        {}", hex::encode(&quote[304..306]));
            println!("  ISVSVN:           {}", hex::encode(&quote[306..308]));
            println!("  REPORTDATA:       {}", hex::encode(&quote[368..400]));
            println!("                    {}", hex::encode(&quote[400..432]));
        }
    }
}
