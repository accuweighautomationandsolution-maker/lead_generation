# The Automation Engine (B2B Procurement Research Engine)

A secure, web-based B2B Sales Pipeline and Procurement Research dashboard built with **Python/Flask** and a modern glassmorphic frontend interface. It digitizes the 5-stage **Data-to-Deal Pipeline** outlined in the standard operating procedures.

## 🚀 Features
1. **Secure Access Portal:** Restricts dashboard entry behind authorization gates. Uses PBKDF2 (HMAC-SHA256) password hashing and secure HTTP session handling (HTTPOnly, SameSite cookie protection).
2. **Dynamic Dashboard Overview:** Renders pipeline progression statistics and a custom visual representation of the Data-to-Deal pipeline flow.
3. **Raw Ingestion Ingest (Stage 1):** Scrapes/accepts new target company profiles with automatic priority checks.
4. **Interactive Node Mapping (Stage 2):** Connects leads to decision makers with dynamic placeholder safety guards ("STRICT MANDATE: Write *Not Publicly Available* if unknown").
5. **Quality Control Verification (Stage 3):** Dual source matching with conflict flagging and confidence scoring (High, Medium, Low).
6. **Sorter Matrix Scorer (Stage 4):** Text-classification parser that categorizes leads into Priority A, B, or C.
7. **Deliverable Data Grid (Stage 5):** An interactive tabular datagrid showing the complete 17-column B2B Sales Intelligence schema, searchable and exportable directly to CSV (Excel).

---

## 🛠️ Installation & Setup

Since the system has two profile spaces (`ADMIN` and `saurabh.b`), you can run the server directly using your local Python configuration:

1. **Open PowerShell in `D:\sales\lead_generation` or `x:\lead_generation`**
2. **Install the required packages:**
   ```powershell
   python -m pip install -r requirements.txt
   ```
   *Note: If you run into an enterprise SSL certificate error on your proxy during install, bypass it using:*
   ```powershell
   pip install -r requirements.txt --trusted-host pypi.org --trusted-host files.pythonhosted.org --trusted-host pypi.python.org
   ```
3. **Start the application server:**
   ```powershell
   python app.py
   ```
4. **Access the application dashboard:**
   Open your browser and navigate to: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 🔐 Default Authorization Credentials
- **Username:** `admin`
- **Password:** `admin123`

You can also use the registration form on the portal login screen to create a new profile with custom credentials.
