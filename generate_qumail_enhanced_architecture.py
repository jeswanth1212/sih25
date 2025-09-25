from diagrams import Diagram, Cluster, Edge
from diagrams.generic.blank import Blank
from diagrams.aws.compute import EC2
from diagrams.aws.database import RDS
from diagrams.aws.network import VPC
from diagrams.aws.security import IAM
from diagrams.aws.storage import S3
from diagrams.generic.compute import Rack
from diagrams.generic.database import SQL
from diagrams.generic.network import Firewall
from diagrams.generic.storage import Storage
from diagrams.onprem.client import Users
from diagrams.onprem.compute import Server
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.inmemory import Redis
from diagrams.onprem.network import Internet
from diagrams.onprem.security import Vault
from diagrams.programming.language import Python, JavaScript
from diagrams.programming.framework import Flask, Electron
from diagrams.saas.communication import Slack
from diagrams.saas.analytics import Snowflake

# Enhanced node attributes for professional black and white theme
node_attrs = {
    "shape": "box",
    "style": "filled",
    "fillcolor": "white",
    "fontcolor": "black",
    "color": "black",
    "penwidth": "2",
    "fontsize": "10",
    "height": "0.6",
    "width": "1.4",
    "fixedsize": "false",
    "labelloc": "c",
    "fontname": "Arial Bold"
}

# Enhanced cluster attributes for professional black and white theme
cluster_attrs = {
    "bgcolor": "white",
    "fontcolor": "black",
    "color": "black",
    "penwidth": "3",
    "fontsize": "12",
    "style": "dashed",
    "labelloc": "t",
    "fontname": "Arial Bold"
}

# Enhanced edge attributes for professional black and white theme
edge_attrs = {
    "color": "black",
    "fontcolor": "black",
    "fontsize": "9",
    "penwidth": "1.5",
    "minlen": "2",
    "fontname": "Arial"
}

# Special edge attributes for different types of connections
api_edge_attrs = {
    "color": "black",
    "fontcolor": "black",
    "fontsize": "9",
    "penwidth": "2",
    "style": "solid",
    "fontname": "Arial"
}

data_edge_attrs = {
    "color": "black",
    "fontcolor": "black",
    "fontsize": "9",
    "penwidth": "1.5",
    "style": "dashed",
    "fontname": "Arial"
}

security_edge_attrs = {
    "color": "black",
    "fontcolor": "black",
    "fontsize": "9",
    "penwidth": "2.5",
    "style": "bold",
    "fontname": "Arial"
}

with Diagram(
    name="QuMail: Enhanced Professional System Architecture",
    direction="TB",  # Top to Bottom layout for better flow
    graph_attr={
        "bgcolor": "white",
        "splines": "ortho",  # Orthogonal splines for cleaner lines
        "overlap": "false",
        "rankdir": "TB",
        "fontsize": "14",
        "fontname": "Arial Bold",
        "pad": "1.0",
        "nodesep": "1.2",  # Increased node separation
        "ranksep": "1.5",  # Increased rank separation
        "concentrate": "true",  # Concentrate edges for cleaner look
        "compound": "true"  # Allow edges between clusters
    },
    node_attr=node_attrs,
    edge_attr=edge_attrs,
    show=False,
    filename="QuMail_Enhanced_Professional_Architecture"
) as diag:

    # User Layer - Enhanced
    with Cluster("USER INTERACTION LAYER", graph_attr=cluster_attrs):
        user_input = Users("User Input\\n(Login/Auth, Compose, Read)")
        user_voice = Blank("Voice Commands\\n(Web Speech API)")
        user_gesture = Blank("Gesture Control\\n(Future Enhancement)")
        user_mobile = Blank("Mobile Interface\\n(Responsive Design)")

    # Frontend Layer - Enhanced with more components
    with Cluster("FRONTEND - Electron Desktop Application", graph_attr=cluster_attrs):
        
        # UI Components Layer - Enhanced
        with Cluster("UI COMPONENTS LAYER", graph_attr=cluster_attrs):
            ui_glass = Blank("Glassmorphism UI\\n(Violet/Purple Theme)")
            ui_list = Blank("Email List View\\n(Thumbnails, Sorting)")
            ui_reader = Blank("Email Reader\\n(Content Display)")
            ui_compose = Blank("Compose Form\\n(Rich Text Editor)")
            ui_profile = Blank("Profile Manager\\n(User Settings)")
            ui_modal = Blank("Modal System\\n(Dialogs, Overlays)")
            ui_sidebar = Blank("Sidebar Navigation\\n(Folder Tree)")
            ui_toolbar = Blank("Toolbar\\n(Actions, Search)")
            ui_status = Blank("Status Bar\\n(Connection, Sync)")
            ui_notifications = Blank("Notification System\\n(Alerts, Toasts)")

        # Manager Layer - Enhanced
        with Cluster("MANAGER LAYER", graph_attr=cluster_attrs):
            mgr_email = Blank("Email Manager\\n(IMAP/SMTP, Folder Sync)")
            mgr_compose = Blank("Compose Manager\\n(Form Validation, Send Control)")
            mgr_profile = Blank("Profile Manager\\n(Auth Control, Session Mgmt)")
            mgr_search = Blank("Search Manager\\n(Full-text Search)")
            mgr_attachment = Blank("Attachment Manager\\n(Upload, Download)")
            mgr_offline = Blank("Offline Manager\\n(Cache, Sync)")

        # Integration Layer - Enhanced
        with Cluster("INTEGRATION LAYER", graph_attr=cluster_attrs):
            int_3d_anim = Blank("3D Animation\\n(Three.js, Key Visual)")
            int_email_api = Blank("Email API Client\\n(Backend Communication)")
            int_crypto_api = Blank("Crypto API Client\\n(Frontend Encryption)")
            int_websocket = Blank("WebSocket Client\\n(Real-time Updates)")
            int_cache = Blank("Local Cache\\n(IndexedDB, Storage)")
            int_worker = Blank("Web Worker\\n(Background Processing)")

        # Testing & Development Layer - Enhanced
        with Cluster("TESTING & DEVELOPMENT LAYER", graph_attr=cluster_attrs):
            test_gui = Blank("GUI Test Suite\\n(Automated UI Tests)")
            test_live = Blank("Live Integration\\n(End-to-end Tests)")
            test_mock = Blank("Mock Encryption\\n(Simulation)")
            test_voice = Blank("Voice Commands\\n(Speech Recognition)")
            test_performance = Blank("Performance Tests\\n(Benchmarks)")
            test_security = Blank("Security Tests\\n(Penetration Testing)")

        # Frontend internal connections - Enhanced
        user_input >> Edge(label="User Actions", **api_edge_attrs) >> ui_glass
        user_voice >> Edge(label="Voice Input", **api_edge_attrs) >> ui_toolbar
        user_gesture >> Edge(label="Touch/Gesture", **api_edge_attrs) >> ui_modal
        user_mobile >> Edge(label="Mobile Interface", **api_edge_attrs) >> ui_glass
        
        ui_glass >> Edge(label="UI Events", **data_edge_attrs) >> mgr_email
        ui_list >> Edge(label="Email Selection", **data_edge_attrs) >> ui_reader
        ui_compose >> Edge(label="Form Data", **data_edge_attrs) >> mgr_compose
        ui_profile >> Edge(label="Profile Actions", **data_edge_attrs) >> mgr_profile
        ui_sidebar >> Edge(label="Navigation", **data_edge_attrs) >> mgr_email
        ui_toolbar >> Edge(label="Search Query", **data_edge_attrs) >> mgr_search
        
        mgr_email >> Edge(label="Email Data", **data_edge_attrs) >> ui_list
        mgr_compose >> Edge(label="Send Logic", **api_edge_attrs) >> int_email_api
        mgr_profile >> Edge(label="Auth Logic", **security_edge_attrs) >> int_crypto_api
        mgr_search >> Edge(label="Search Results", **data_edge_attrs) >> ui_list
        mgr_attachment >> Edge(label="File Operations", **data_edge_attrs) >> ui_compose
        mgr_offline >> Edge(label="Cache Management", **data_edge_attrs) >> int_cache
        
        int_3d_anim << Edge(label="Animation Trigger", **api_edge_attrs) << mgr_compose
        int_websocket >> Edge(label="Real-time Data", **data_edge_attrs) >> ui_notifications
        int_cache >> Edge(label="Cached Data", **data_edge_attrs) >> mgr_offline
        int_worker >> Edge(label="Background Tasks", **data_edge_attrs) >> mgr_email

    # Backend Layer - Enhanced with more components
    with Cluster("BACKEND - Flask RESTful API Server", graph_attr=cluster_attrs):
        
        # API Gateway Layer - New
        with Cluster("API GATEWAY LAYER", graph_attr=cluster_attrs):
            api_gateway = Blank("API Gateway\\n(Rate Limiting, Auth)")
            api_load_balancer = Blank("Load Balancer\\n(Traffic Distribution)")
            api_monitoring = Blank("API Monitoring\\n(Metrics, Logs)")
            api_documentation = Blank("API Documentation\\n(Swagger/OpenAPI)")

        # API Endpoints Layer - Enhanced
        with Cluster("API ENDPOINTS LAYER", graph_attr=cluster_attrs):
            api_send = Blank("/api/email/send\\n(Email Transmission)")
            api_inbox = Blank("/api/email/inbox\\n(Email Retrieval)")
            api_qkd_keys = Blank("/api/qkd/keys\\n(Quantum Key Management)")
            api_encrypt = Blank("/api/encrypt\\n(Encryption Service)")
            api_decrypt = Blank("/api/decrypt\\n(Decryption Service)")
            api_status = Blank("/api/status\\n(System Health)")
            api_folders = Blank("/api/folders\\n(Folder Management)")
            api_search = Blank("/api/search\\n(Full-text Search)")
            api_attachments = Blank("/api/attachments\\n(File Handling)")
            api_webhooks = Blank("/api/webhooks\\n(Event Notifications)")

        # Core Services Layer - Enhanced
        with Cluster("CORE SERVICES LAYER", graph_attr=cluster_attrs):
            svc_email = Blank("Email Service\\n(SMTP/IMAP, Multi-provider)")
            svc_auth = Blank("Authentication Service\\n(JWT, OAuth2, App Passwords)")
            svc_config = Blank("Configuration Service\\n(Firebase, Environment)")
            svc_logging = Blank("Logging Service\\n(Structured Logs)")
            svc_monitoring = Blank("Monitoring Service\\n(Health Checks)")
            svc_backup = Blank("Backup Service\\n(Data Protection)")
            svc_queue = Blank("Message Queue\\n(Async Processing)")

        # Encryption Engine - Enhanced
        with Cluster("ENCRYPTION ENGINE", graph_attr=cluster_attrs):
            enc_multi_level = Blank("Multi-Level Encryption\\n(4 Security Levels)")
            enc_hybrid_kdf = Blank("Hybrid Key Derivation\\n(HKDF-SHA256)")
            enc_mime_handler = Blank("MIME Handler\\n(Email Structure)")
            enc_key_rotation = Blank("Key Rotation\\n(Automatic Key Updates)")
            enc_audit = Blank("Encryption Audit\\n(Security Logging)")
            enc_performance = Blank("Performance Monitor\\n(Encryption Metrics)")

        # Cryptographic Modules - Enhanced
        with Cluster("CRYPTOGRAPHIC MODULES", graph_attr=cluster_attrs):
            crypto_qkd_sim = Blank("QKD Simulator\\n(BB84 Protocol)")
            crypto_ecdh = Blank("ECDH/X25519\\n(Classical Key Exchange)")
            crypto_ml_kem = Blank("ML-KEM PQC\\n(Post-Quantum Crypto)")
            crypto_real_pqc = Blank("Real PQC\\n(Production Implementation)")
            crypto_hybrid_engine = Blank("Hybrid Engine\\n(Key Combination)")
            crypto_aes = Blank("AES Variants\\n(Symmetric Encryption)")
            crypto_signatures = Blank("Digital Signatures\\n(EdDSA, ML-DSA)")
            crypto_hashes = Blank("Hash Functions\\n(SHA-256, SHA-3)")

        # Backend internal connections - Enhanced
        api_gateway >> Edge(label="Request Routing", **api_edge_attrs) >> api_load_balancer
        api_load_balancer >> Edge(label="Load Distribution", **api_edge_attrs) >> api_send
        api_load_balancer >> Edge(label="Load Distribution", **api_edge_attrs) >> api_inbox
        api_monitoring >> Edge(label="Metrics Collection", **data_edge_attrs) >> api_gateway
        
        api_send >> Edge(label="Email Send Request", **api_edge_attrs) >> svc_email
        api_inbox >> Edge(label="Email Fetch Request", **api_edge_attrs) >> svc_email
        api_qkd_keys >> Edge(label="Key Request", **security_edge_attrs) >> crypto_qkd_sim
        api_encrypt >> Edge(label="Encryption Request", **security_edge_attrs) >> enc_multi_level
        api_decrypt >> Edge(label="Decryption Request", **security_edge_attrs) >> enc_multi_level
        api_status >> Edge(label="Health Check", **api_edge_attrs) >> svc_monitoring
        api_folders >> Edge(label="Folder List Request", **api_edge_attrs) >> svc_email
        api_search >> Edge(label="Search Query", **data_edge_attrs) >> svc_email
        api_attachments >> Edge(label="File Operations", **data_edge_attrs) >> svc_email
        api_webhooks >> Edge(label="Event Notifications", **data_edge_attrs) >> svc_queue

        svc_email >> Edge(label="IMAP/SMTP Operations", **data_edge_attrs) >> enc_mime_handler
        svc_auth >> Edge(label="Authentication Tokens", **security_edge_attrs) >> enc_multi_level
        svc_config >> Edge(label="Configuration Data", **data_edge_attrs) >> enc_multi_level
        svc_logging >> Edge(label="Log Data", **data_edge_attrs) >> svc_monitoring
        svc_backup >> Edge(label="Backup Data", **data_edge_attrs) >> svc_queue

        enc_multi_level >> Edge(label="Key Derivation", **security_edge_attrs) >> enc_hybrid_kdf
        enc_multi_level >> Edge(label="Content Processing", **data_edge_attrs) >> enc_mime_handler
        enc_hybrid_kdf >> Edge(label="Key Generation", **security_edge_attrs) >> crypto_hybrid_engine
        enc_mime_handler >> Edge(label="Crypto Primitives", **security_edge_attrs) >> crypto_aes
        enc_key_rotation >> Edge(label="Key Updates", **security_edge_attrs) >> crypto_hybrid_engine
        enc_audit >> Edge(label="Security Events", **security_edge_attrs) >> svc_logging

        crypto_hybrid_engine >> Edge(label="QKD Keys", **security_edge_attrs) >> crypto_qkd_sim
        crypto_hybrid_engine >> Edge(label="PQC Keys", **security_edge_attrs) >> crypto_ml_kem
        crypto_hybrid_engine >> Edge(label="Classical Keys", **security_edge_attrs) >> crypto_ecdh
        crypto_signatures >> Edge(label="Signature Verification", **security_edge_attrs) >> enc_multi_level
        crypto_hashes >> Edge(label="Hash Operations", **security_edge_attrs) >> enc_hybrid_kdf

    # Quantum Cryptography Layer - Enhanced
    with Cluster("QUANTUM CRYPTOGRAPHY LAYER", graph_attr=cluster_attrs):
        qkd_sim_layer = Blank("QKD Simulator\\n(BB84 Protocol, Qiskit)")
        key_manager = Blank("Quantum Key Manager\\n(ETSI GS QKD 014)")
        quantum_network = Blank("Quantum Network\\n(Quantum Channels)")
        quantum_entanglement = Blank("Quantum Entanglement\\n(EPR Pairs)")
        quantum_error_correction = Blank("Error Correction\\n(Quantum Codes)")

        with Cluster("SECURITY LEVEL BRANCHING", graph_attr=cluster_attrs):
            lvl1_qkd = Blank("Level 1: QKD\\n(Perfect Security)")
            lvl2_hybrid = Blank("Level 2: Hybrid\\n(QKD + Classical)")
            lvl3_pqc = Blank("Level 3: PQC\\n(Post-Quantum)")
            lvl4_classic = Blank("Level 4: Classic\\n(Traditional)")

        qkd_sim_layer >> Edge(label="Key Generation", **security_edge_attrs) >> key_manager
        quantum_network >> Edge(label="Key Transport", **security_edge_attrs) >> key_manager
        quantum_entanglement >> Edge(label="Entangled States", **security_edge_attrs) >> quantum_network
        quantum_error_correction >> Edge(label="Error Mitigation", **security_edge_attrs) >> quantum_network
        key_manager >> Edge(label="Security Policy", **security_edge_attrs) >> lvl1_qkd
        key_manager >> Edge(label="Security Policy", **security_edge_attrs) >> lvl2_hybrid
        key_manager >> Edge(label="Security Policy", **security_edge_attrs) >> lvl3_pqc
        key_manager >> Edge(label="Security Policy", **security_edge_attrs) >> lvl4_classic

    # External Services & Integrations - Enhanced
    with Cluster("EXTERNAL SERVICES & INTEGRATIONS", graph_attr=cluster_attrs):
        email_providers = Blank("Email Providers\\n(Gmail, Yahoo, Outlook)")
        firebase = Blank("Firebase\\n(Real-time Database)")
        cloud_storage = Blank("Cloud Storage\\n(File Attachments)")
        cdn = Blank("Content Delivery Network\\n(Static Assets)")
        
        with Cluster("SECURITY PROTOCOLS", graph_attr=cluster_attrs):
            sec_mtls = Blank("mTLS\\n(Mutual TLS)")
            sec_jwt = Blank("JWT\\n(JSON Web Tokens)")
            sec_oauth2 = Blank("OAuth2\\n(Authorization)")
            sec_app_pass = Blank("App Passwords\\n(Gmail Integration)")
            sec_2fa = Blank("2FA\\n(Two-Factor Auth)")
            sec_biometric = Blank("Biometric Auth\\n(Future Enhancement)")

        with Cluster("STANDARDS COMPLIANCE", graph_attr=cluster_attrs):
            etsi_standard = Blank("ETSI GS QKD 014\\n(Quantum Standards)")
            nist_standard = Blank("NIST FIPS 203\\n(Post-Quantum)")
            rfc_standard = Blank("RFC 7748\\n(Classical Crypto)")
            iso_standard = Blank("ISO 27001\\n(Security Management)")

    # Data Flow & Processing Pipeline - Enhanced
    with Cluster("DATA FLOW & PROCESSING PIPELINE", graph_attr=cluster_attrs):
        input_proc = Blank("INPUT PROCESSING\\n(Validation, Sanitization)")
        enc_flow = Blank("ENCRYPTION FLOW\\n(Key Gen, Encrypt, Package)")
        transmission = Blank("TRANSMISSION\\n(SMTP, Network)")
        reception = Blank("RECEPTION\\n(IMAP, Decrypt, Parse)")

        with Cluster("REAL-TIME PROCESSING PIPELINE", graph_attr=cluster_attrs):
            rt_animation = Blank("Animation\\n(3D Visualization)")
            rt_key_gen = Blank("Key Generation\\n(QKD+ECDH+ML-KEM)")
            rt_hybrid_kdf = Blank("Hybrid KDF\\n(HKDF-SHA256)")
            rt_encryption = Blank("Encryption\\n(AES-256-GCM)")
            rt_mime_pack = Blank("MIME Packaging\\n(Email Structure)")
            rt_smtp_send = Blank("SMTP Send\\n(Email Delivery)")
            rt_monitoring = Blank("Real-time Monitoring\\n(Performance Metrics)")

        input_proc >> Edge(label="Validated Data", **data_edge_attrs) >> enc_flow
        enc_flow >> Edge(label="Encrypted Message", **data_edge_attrs) >> transmission
        transmission >> Edge(label="Email Delivery", **data_edge_attrs) >> reception

        # Real-time pipeline flow
        input_proc >> Edge(label="Security Level", **data_edge_attrs) >> rt_key_gen
        rt_key_gen >> Edge(label="Derived Key", **security_edge_attrs) >> rt_hybrid_kdf
        rt_hybrid_kdf >> Edge(label="Encryption Key", **security_edge_attrs) >> rt_encryption
        rt_encryption >> Edge(label="Encrypted Body", **data_edge_attrs) >> rt_mime_pack
        rt_mime_pack >> Edge(label="Formatted Email", **data_edge_attrs) >> rt_smtp_send
        rt_monitoring >> Edge(label="Performance Data", **data_edge_attrs) >> rt_encryption

    # Performance & Metrics - Enhanced
    with Cluster("PERFORMANCE & METRICS", graph_attr=cluster_attrs):
        perf_enc_speed = Blank("Encryption Speed\\n(66,397 ops/sec)")
        perf_key_gen = Blank("Key Generation\\n(Real-time)")
        perf_email_proc = Blank("Email Processing\\n(Multi-threaded)")
        perf_mem_usage = Blank("Memory Usage\\n(Optimized)")
        perf_network = Blank("Network Performance\\n(Latency, Throughput)")
        perf_security = Blank("Security Metrics\\n(Threat Detection)")

    # Deployment & Future Scaling - Enhanced
    with Cluster("DEPLOYMENT & FUTURE SCALING", graph_attr=cluster_attrs):
        dep_platform = Blank("Current Platform\\n(Windows 10/11)")
        dep_modularity = Blank("Modularity\\n(Chat/Video Ready)")
        dep_cloud = Blank("Cloud Deploy\\n(Kubernetes)")
        dep_enterprise = Blank("Enterprise\\n(ISRO Centers)")
        dep_mobile = Blank("Mobile Apps\\n(iOS/Android)")
        dep_iot = Blank("IoT Integration\\n(Sensors, Devices)")

    # 2025 Novel Breakthrough Innovation - Enhanced
    with Cluster("2025 NOVEL BREAKTHROUGH INNOVATION", graph_attr=cluster_attrs):
        innov_hybrid_crypto = Blank("Triple-Layer Hybrid\\n(QKD+ECDH+Real-PQC)")
        innov_standards = Blank("Standards Compliance\\n(ETSI+NIST+RFC)")
        innov_research = Blank("Research Publication\\n(arXiv:2509.10551)")
        innov_patents = Blank("Patent Applications\\n(IP Protection)")
        innov_collaboration = Blank("Industry Collaboration\\n(Partnerships)")

    # --- Global Connections - Enhanced ---

    # Frontend to Backend - Enhanced
    int_email_api >> Edge(label="HTTPS API (Email)", **api_edge_attrs) >> api_gateway
    int_crypto_api >> Edge(label="HTTPS API (Crypto)", **security_edge_attrs) >> api_gateway
    int_websocket >> Edge(label="WebSocket (Real-time)", **data_edge_attrs) >> api_gateway
    mgr_profile >> Edge(label="Auth Status", **security_edge_attrs) >> api_gateway
    mgr_email >> Edge(label="Folder Operations", **data_edge_attrs) >> api_gateway
    mgr_search >> Edge(label="Search Requests", **data_edge_attrs) >> api_gateway
    mgr_attachment >> Edge(label="File Operations", **data_edge_attrs) >> api_gateway

    # Backend to Quantum Layer - Enhanced
    crypto_qkd_sim >> Edge(label="QKD Simulation", **security_edge_attrs) >> qkd_sim_layer
    crypto_qkd_sim >> Edge(label="Key Request", **security_edge_attrs) >> key_manager
    lvl1_qkd >> Edge(label="QKD Key Usage", **security_edge_attrs) >> crypto_qkd_sim
    lvl2_hybrid >> Edge(label="Hybrid Key Usage", **security_edge_attrs) >> crypto_hybrid_engine
    lvl3_pqc >> Edge(label="PQC Key Usage", **security_edge_attrs) >> crypto_ml_kem
    lvl4_classic >> Edge(label="Classical Key Usage", **security_edge_attrs) >> crypto_ecdh

    # Backend to External Services - Enhanced
    svc_email >> Edge(label="SMTP/IMAP", **data_edge_attrs) >> email_providers
    svc_auth >> Edge(label="Database Access", **data_edge_attrs) >> firebase
    svc_config >> Edge(label="Configuration", **data_edge_attrs) >> firebase
    svc_backup >> Edge(label="File Storage", **data_edge_attrs) >> cloud_storage
    api_documentation >> Edge(label="Static Assets", **data_edge_attrs) >> cdn
    svc_auth >> Edge(label="Auth Protocols", **security_edge_attrs) >> sec_jwt
    svc_auth >> Edge(label="Auth Protocols", **security_edge_attrs) >> sec_oauth2
    svc_auth >> Edge(label="Auth Protocols", **security_edge_attrs) >> sec_app_pass
    svc_auth >> Edge(label="Auth Protocols", **security_edge_attrs) >> sec_2fa
    svc_email >> Edge(label="Secure Transport", **security_edge_attrs) >> sec_mtls
    enc_multi_level >> Edge(label="Standards Adherence", **security_edge_attrs) >> etsi_standard
    enc_multi_level >> Edge(label="Standards Adherence", **security_edge_attrs) >> nist_standard
    enc_multi_level >> Edge(label="Standards Adherence", **security_edge_attrs) >> rfc_standard

    # Data Flow Pipeline to other layers - Enhanced
    input_proc >> Edge(label="User Input", **data_edge_attrs) >> user_input
    input_proc >> Edge(label="Security Selection", **security_edge_attrs) >> lvl1_qkd
    input_proc >> Edge(label="Security Selection", **security_edge_attrs) >> lvl2_hybrid
    input_proc >> Edge(label="Security Selection", **security_edge_attrs) >> lvl3_pqc
    input_proc >> Edge(label="Security Selection", **security_edge_attrs) >> lvl4_classic
    enc_flow >> Edge(label="Encryption Logic", **security_edge_attrs) >> enc_multi_level
    transmission >> Edge(label="Email Delivery", **data_edge_attrs) >> email_providers
    reception >> Edge(label="Display Content", **data_edge_attrs) >> ui_reader

    # Real-time pipeline to other layers - Enhanced
    rt_animation >> Edge(label="Visual Feedback", **data_edge_attrs) >> int_3d_anim
    rt_key_gen >> Edge(label="Key Generation", **security_edge_attrs) >> crypto_qkd_sim
    rt_key_gen >> Edge(label="Key Generation", **security_edge_attrs) >> crypto_ecdh
    rt_key_gen >> Edge(label="Key Generation", **security_edge_attrs) >> crypto_ml_kem
    rt_hybrid_kdf >> Edge(label="KDF Logic", **security_edge_attrs) >> enc_hybrid_kdf
    rt_encryption >> Edge(label="Encryption Logic", **security_edge_attrs) >> enc_multi_level
    rt_mime_pack >> Edge(label="MIME Structuring", **data_edge_attrs) >> enc_mime_handler
    rt_smtp_send >> Edge(label="Email Send", **data_edge_attrs) >> svc_email
    rt_monitoring >> Edge(label="Performance Data", **data_edge_attrs) >> perf_enc_speed

    # Performance & Metrics to relevant layers - Enhanced
    perf_enc_speed >> Edge(label="Monitor", **data_edge_attrs) >> enc_multi_level
    perf_key_gen >> Edge(label="Monitor", **data_edge_attrs) >> crypto_qkd_sim
    perf_email_proc >> Edge(label="Monitor", **data_edge_attrs) >> svc_email
    perf_mem_usage >> Edge(label="Monitor", **data_edge_attrs) >> mgr_email
    perf_network >> Edge(label="Monitor", **data_edge_attrs) >> svc_email
    perf_security >> Edge(label="Monitor", **security_edge_attrs) >> enc_audit

    # Deployment & Scaling to relevant layers - Enhanced
    dep_platform >> Edge(label="Runs On", **data_edge_attrs) >> ui_glass
    dep_modularity >> Edge(label="Design Principle", **data_edge_attrs) >> mgr_email
    dep_cloud >> Edge(label="Deployment Target", **data_edge_attrs) >> api_load_balancer
    dep_enterprise >> Edge(label="Target Use Case", **security_edge_attrs) >> lvl1_qkd
    dep_mobile >> Edge(label="Future Platform", **data_edge_attrs) >> user_mobile
    dep_iot >> Edge(label="IoT Integration", **data_edge_attrs) >> user_gesture

    # Innovation to relevant layers - Enhanced
    innov_hybrid_crypto >> Edge(label="Future Integration", **security_edge_attrs) >> enc_multi_level
    innov_hybrid_crypto >> Edge(label="Future Integration", **security_edge_attrs) >> lvl2_hybrid
    innov_standards >> Edge(label="Guidance", **security_edge_attrs) >> etsi_standard
    innov_research >> Edge(label="Knowledge Base", **data_edge_attrs) >> crypto_hybrid_engine
    innov_patents >> Edge(label="IP Protection", **security_edge_attrs) >> crypto_real_pqc
    innov_collaboration >> Edge(label="Partnerships", **data_edge_attrs) >> email_providers

    # Connect testing layer to relevant components - Enhanced
    test_gui >> Edge(label="UI Testing", **data_edge_attrs) >> ui_glass
    test_live >> Edge(label="Integration Testing", **api_edge_attrs) >> int_email_api
    test_mock >> Edge(label="Mock Testing", **data_edge_attrs) >> crypto_qkd_sim
    test_voice >> Edge(label="Voice Testing", **data_edge_attrs) >> user_voice
    test_performance >> Edge(label="Performance Testing", **data_edge_attrs) >> perf_enc_speed
    test_security >> Edge(label="Security Testing", **security_edge_attrs) >> enc_audit

    # Additional cross-layer connections for better flow
    ui_notifications >> Edge(label="User Alerts", **data_edge_attrs) >> user_input
    svc_queue >> Edge(label="Async Processing", **data_edge_attrs) >> mgr_offline
    api_webhooks >> Edge(label="Event Streams", **data_edge_attrs) >> int_websocket
    enc_performance >> Edge(label="Crypto Metrics", **data_edge_attrs) >> perf_enc_speed
    svc_monitoring >> Edge(label="Health Data", **data_edge_attrs) >> api_monitoring

print("✅ Enhanced QuMail Architecture Diagram Generated Successfully!")
print("📁 Output file: QuMail_Enhanced_Professional_Architecture.png")
print("🎨 Theme: Professional Black & White")
print("🔗 Features: Enhanced connections, better spacing, clear labels")
print("📊 Components: 100+ detailed components with comprehensive flow")

