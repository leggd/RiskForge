
import bcrypt
print(bcrypt.hashpw("admin".encode(), bcrypt.gensalt()).decode())

# RUN THIS IN SQL SERVER WITH ABOVE PASSWORD HASH # 
#INSERT INTO users (username, password_hash, role)
#VALUES ('admin', 'PASTE_HASH_HERE', 'ADMIN');