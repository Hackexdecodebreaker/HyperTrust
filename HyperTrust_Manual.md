# HyperTrust: Attribute-Based Smart Network Access Control

## 1. Introduction
HyperTrust is an advanced network access control system that leverages Ciphertext-Policy Attribute-Based Encryption (CP-ABE). It regulates access to campus resources and WiFi using user attributes rather than traditional passwords alone.

## 2. Cryptography for Beginners: How CP-ABE Works
In traditional encryption, a message is locked with a specific key. Only the person holding that matching key can open it.
In **Attribute-Based Encryption (ABE)**, the lock is a **Policy** (like a set of rules), and the key is a set of **Attributes** (like a digital ID card).

**How it operates in HyperTrust:**
- **Master Keys**: The system generates a Master Secret Key (MSK) and a Public Key (PK).
- **Attributes**: Each user is assigned attributes (e.g., 'Student', 'Computer Science', 'Paid Dues').
- **User Keys**: A unique private key is generated for the user based on their attributes, using the MSK.
- **Encryption**: When protecting a resource (like WiFi), the system encrypts the access token using a Policy (e.g., "dept:cse AND paid:true").
- **Decryption**: To access the resource, the user's private key evaluates the policy. If the user's attributes satisfy the rules, the token is decrypted automatically.

**Collusion Resistance**: Users cannot combine their keys to bypass rules. The system mathematically binds all of an individual user's attributes to a unique random salt.

## 3. Technical Architecture
HyperTrust utilizes a **Hybrid Encryption** model for maximum performance and security:
- **AES-GCM (Symmetric Encryption)**: The actual WiFi token or resource payload is encrypted using a fast random 256-bit AES key.
- **CP-ABE (Asymmetric Policy Encryption)**: The randomly generated AES key is then encrypted using the CP-ABE policy.

**Storing Policies**
- **WiFi Policy**: The default access rule for campus WiFi is strictly `paid:true`. Any user validated as having paid may access it regardless of department. Admin updates take effect instantly.
- **Resource Policies**: Specific portals (e.g., Confidential Docs, Engineering Labs) have their own strict logic gates.

## 4. User Registration & Roles
When a new user registers on the platform:
1. They are automatically assigned the **Student** role (this is enforced and cannot be manipulated during user registration).
2. They select their department.
3. Their payment status defaults to false.
4. A new CP-ABE key is immediately generated containing the attributes role:student, dept:[their_dept], and paid:false.

## 5. Administrator Controls
System Administrators have total control over access rules:
- **Dashboard**: Monitor access logs in real-time, view encryption benchmarks, and see active users.
- **Policy Builder**: A visual interface the admin uses to compose access configurations (combining attributes with AND/OR logic).
- **Updates**: Changes to policies take effect instantly system-wide without needing to reissue user keys. When a policy changes, the underlying token is re-encrypted with the new rules.

## 6. Payment Simulation
Certain resources require a 'paid:true' attribute. Users can simulate a payment through their dashboard. Upon successful payment, the system dynamically generates a new CP-ABE key embedding the updated attribute, granting immediate access to paid resources.

## 7. Security Considerations
The Master Secret Key (MSK) must never leave the server. If compromised, the entire infrastructure must be re-keyed. Private Keys are mathematically tied to the user's database ID to ensure accountability and track usage.
