import sys
import os
import markdown

try:
    from fpdf import FPDF, HTMLMixin
except ImportError:
    print("fpdf2 not installed yet")
    sys.exit(1)

# Basic HTML to PDF Mixin
class PDF(FPDF, HTMLMixin):
    def header(self):
        self.set_font('Helvetica', 'B', 15)
        self.cell(80)
        self.cell(30, 10, 'HyperTrust System Manual', 0, 0, 'C')
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, 'Page ' + str(self.page_no()) + '/{nb}', 0, 0, 'C')

def create_pdf(output_path):
    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font('Helvetica', '', 12)
    
    content = """
    <h1>HyperTrust: Attribute-Based Smart Network Access Control</h1>
    
    <h2>1. Introduction</h2>
    <p>HyperTrust is an advanced network access control system that leverages Ciphertext-Policy Attribute-Based Encryption (CP-ABE). It regulates access to campus resources and WiFi using user attributes rather than traditional passwords alone.</p>
    
    <h2>2. Cryptography for Beginners: How CP-ABE Works</h2>
    <p>In traditional encryption, a message is locked with a specific key. Only the person holding that matching key can open it.</p>
    <p>In <strong>Attribute-Based Encryption (ABE)</strong>, the lock is a <strong>Policy</strong> (like a set of rules), and the key is a set of <strong>Attributes</strong> (like a digital ID card).</p>
    
    <p><b>How it operates in HyperTrust:</b></p>
    <ul>
        <li><strong>Master Keys</strong>: The system generates a Master Secret Key (MSK) and a Public Key (PK).</li>
        <li><strong>Attributes</strong>: Each user is assigned attributes (e.g., 'Student', 'Computer Science', 'Paid Dues').</li>
        <li><strong>User Keys</strong>: A unique private key is generated for the user based on their attributes, using the MSK.</li>
        <li><strong>Encryption</strong>: When protecting a resource (like WiFi), the system encrypts the access token using a Policy (e.g., "dept:cse AND paid:true").</li>
        <li><strong>Decryption</strong>: To access the resource, the user's private key evaluates the policy. If the user's attributes satisfy the rules, the token is decrypted automatically.</li>
    </ul>
    
    <p><strong>Collusion Resistance</strong>: Users cannot combine their keys to bypass rules. The system mathematically binds all of an individual user's attributes to a unique random salt.</p>
    
    <h2>3. Technical Architecture</h2>
    <p>HyperTrust utilizes a <strong>Hybrid Encryption</strong> model for maximum performance and security:</p>
    <ul>
        <li><strong>AES-GCM (Symmetric Encryption)</strong>: The actual WiFi token or resource payload is encrypted using a fast random 256-bit AES key.</li>
        <li><strong>CP-ABE (Asymmetric Policy Encryption)</strong>: The randomly generated AES key is then encrypted using the CP-ABE policy.</li>
    </ul>
    
    <p><b>Storing Policies</b></p>
    <ul>
        <li><strong>WiFi Policy</strong>: The default access rule for campus WiFi is stored globally as <code>paid:true</code>. Validated users who have paid may access it regardless of department. Admin updates take effect instantaneously.</li>
        <li><strong>Resource Policies</strong>: Specific portals (e.g., Confidential Docs, Engineering Labs) have their own strict logic gates.</li>
    </ul>
    
    <h2>4. User Registration & Roles</h2>
    <p>When a new user registers on the platform:</p>
    <ol>
        <li>They are automatically assigned the <strong>Student</strong> role (this is strictly enforced and cannot be changed during registration).</li>
        <li>They select their department.</li>
        <li>Their payment status defaults to false.</li>
        <li>A new CP-ABE key is immediately generated containing the attributes role:student, dept:[their_dept], and paid:false.</li>
    </ol>
    
    <h2>5. Administrator Controls</h2>
    <p>System Administrators have total control over access rules:</p>
    <ul>
        <li><strong>Dashboard</strong>: Monitor access logs in real-time, view encryption benchmarks, and see active users.</li>
        <li><strong>Policy Builder</strong>: A visual interface the admin uses to compose access configurations (combining attributes with AND/OR logic).</li>
        <li><strong>Updates</strong>: Changes to policies take effect instantly system-wide without needing to reissue user keys. When a policy changes, the underlying token is re-encrypted with the new rules.</li>
    </ul>

    <h2>6. Payment Simulation</h2>
    <p>Certain resources require a 'paid:true' attribute. Users can simulate a payment through their dashboard. Upon successful payment, the system dynamically generates a new CP-ABE key embedding the updated attribute, granting immediate access to paid resources.</p>
    
    <h2>7. Security Considerations</h2>
    <p>The Master Secret Key (MSK) must never leave the server. If compromised, the entire infrastructure must be re-keyed. Private Keys are mathematically tied to the user's database ID to ensure accountability and track usage.</p>
    """
    
    pdf.write_html(content)
    pdf.output(output_path)
    print(f"PDF Manual successfully created at {output_path}")

if __name__ == "__main__":
    create_pdf(r"c:\\xampp\\htdocs\\HyperTrust\\HyperTrust_Manual.pdf")
