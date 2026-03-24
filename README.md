# HyperTrust — CP-ABE Network Access Control

HyperTrust is a highly secure web application that uses **Ciphertext-Policy Attribute-Based Encryption (CP-ABE)** to gate access to network resources, such as Wi-Fi tokens and secure research portals.

Instead of traditional access control lists (ACLs) or role-based access control (RBAC), HyperTrust encrypts access configurations directly under a cryptographic *policy* (e.g., `(dept:cse and paid:true) or role:networkadmin`). Only users whose cryptographic keys intrinsically possess the satisfying attributes can decrypt the token or access the portal.

---

## Architecture & Core Components

### 1. The CP-ABE Simulation Engine (`abe_engine.py`)
This file simulates a pure-Python Attribute-Based Encryption engine. Real ABE uses complex bilinear pairings over elliptic curves, but this engine substitutes standard HKDF (HMAC-based Key Derivation Function) symmetric cryptography and mathematical XOR masking to perfectly replicate the logical constraints of ABE.

- **`cpabe_setup()`**: Generates the Master Secret Key (`MSK`) and Public Parameters (`PK`).
  - `PK` is public and mathematically defines the system domain.
  - `MSK` never leaves the server and seeds all attribute generation.
- **`cpabe_keygen()`**: Binds a user's defined attributes (e.g., `dept:cse`) to unique mathematical sub-keys derived from the `MSK`. Crucially, it uses a unique `user_salt` to prevent **collusion** (so two users cannot combine their keys to satisfy a policy they each fail independently).
- **`cpabe_encrypt()`**: Takes a boolean policy tree, creates a master AES 256-bit encryption key (`policy_key`), and generates individual cryptographic puzzle shares attached to the attributes needed to recover that key.
- **`cpabe_decrypt()`**: The user supplies their `private_key` dict containing their attribute sub-keys. The engine reconstructs the `policy_key` *if and only if* their attributes traverse the access policy tree.

### 2. Hybrid Encryption System (`crypto_utils.py`)
Because ABE algorithms are computationally intensive and operate on fixed-size blocks, HyperTrust uses a **Hybrid Cryptography** schema:
1. The **Data payload** (e.g., the Wi-Fi Token) is encrypted using extremely fast symmetric `AES-256-GCM`.
2. The **AES-GCM symmetric key** is then encrypted using CP-ABE under the access policy.
3. The ciphertext bundled together contains: `{encrypted_token, nonce, tag, encrypted_aes_key, policy}`.

During decryption, `crypto_utils.py` uses the user's CP-ABE key to recover the AES key, which is then used to safely decrypt the underlying AES-GCM token payload.

### 3. Application Routing & Portals (`routes/user.py`, `app.py`)
- **`/request-access`**: The core endpoint where users attempt to generate a Wi-Fi token. The server encrypts a new token string under the current active constraint `WIFI_POLICY` (default is `paid:true`, universally granting paid users access regardless of department). If the user's keys decrypt it, they get access.
- **`/portal/<portal_name>`**: A dynamic route that secures specific web pages. To guarantee these portals are secure, the route locally encrypts a dummy payload under the system policy and attempts to decrypt it with the user's key. If it passes the mathematical hurdle, the Flask application renders the requested HTML portal securely.

### 4. Database Layer (`db.py`, `schema.sql`)
The system utilizes a SQLite database for lightweight, rapid access control state:
- **`system_settings`**: Stores the cryptographic `PK` and `MSK` blobs globally, along with dynamic, real-time configuration like the instantaneous `wifi_policy`.
- **`users`**: Stores login hashes and roles. (Note: New registrations are implicitly restricted to the `Student` role for security).
- **`user_keys`**: Securely houses the compiled CP-ABE private keys for specific users.
- **`access_tokens`**: Keeps an immutable ledger of the actual encrypted token bundles.

---

##  How to Run

1. Ensure you have Python installed, and activate the local virtual environment:
   ```cmd
   cd c:\xampp\htdocs\HyperTrust
   venv\Scripts\Activate.ps1
   ```

2. Initialize the Database and generate the Master cryptographic parameters:
   ```cmd
   python init_db.py
   ```
   *(This script handles running `cpabe_setup` and storing the `MSK`)*

3. Start the application:
   ```cmd
   python app.py
   ```

4. Navigate your browser to `http://127.0.0.1:5000`.

---

##  Accessing the Portals

We have included two highly secure portals strictly bound by CP-ABE encryption. 

- **Research Data Portal** (`/user/portal/research_data`)
- **Confidential Docs Portal** (`/user/portal/confidential_docs`)

These portals share the global `WIFI_POLICY` string. Users must satisfy the evaluation requirements intrinsically baked into their user keys. You can observe their capability on the "My Dashboard" evaluation visualizer. If they satisfy the requirements, the server grants them entry completely deterministically. 

**Demo Roles:**
- An `admin` user is generated by default via `init_db.py`.
- You can create your own users within the Admin dashboard to test arbitrary attribute subsets and attempt decryption in real time.
