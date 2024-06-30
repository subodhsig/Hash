import hashlib

def sha256_hash(message):

    if isinstance(message, str):
        message = message.encode('utf-8')
    
   
    sha256 = hashlib.sha256()
    
    # Update 
    sha256.update(message)
    
   
    hash_hex = sha256.hexdigest()
    
    return hash_hex


message = "Subodh"
hashed_message = sha256_hash(message)
print(f"SHA-256 Hash of '{message}': {hashed_message}")
