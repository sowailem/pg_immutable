
# Master's Thesis Proposal

**Researchers:** Mohammed Jafar Suleiman Al-Nahdi, Abdullah Ahmed Mahfoudh Sowailem  
**Supervisor:** Dr. Abdullah Al-Dhibani

## Proposed Thesis Title
**Enhancing Digital Record Integrity Using Immutable Storage Techniques in Relational DBMS**

---

## 1. Problem Statement
**Data Integrity** is considered one of the fundamental pillars of information security, especially in financial, governmental, and medical systems. However, traditional **Relational Database Management Systems (RDBMS)** face a critical security gap related to **Insider Threats**.

In current infrastructures, **Database Administrators (DBAs)** or accounts with high privileges (**Superusers**) have absolute ability to execute **UPDATE** or **DELETE** operations on any record within tables, regardless of the **Access Control Policies** applied to ordinary users. This privilege model creates a **Single Point of Failure**, where any authorized party, whether motivated by malice or due to account compromise, can manipulate historical records without leaving a clear trace. This undermines trust in the integrity of stored data and threatens compliance with regulatory standards.

## 2. Research Objective & Proposed Solution
This study aims to design and develop a software framework that ensures **Immutability** for data in specific tables within a database, regardless of the privilege level granted to the user attempting access.

The proposed solution is based on the **Append-Only Log** principle, where modifying or deleting records is strictly prohibited once written to specific tables. The solution does not rely on bypassable software privilege policies, but rather on fundamental modifications to the **Database Engine** itself to enforce constraints at the **Storage Engine Level**.

## 3. Technical Implementation Methodology
Given the flexibility of the **PostgreSQL** DBMS as an open-source system, a **Database Extension** development methodology was adopted to modify the **Kernel** behavior. The methodology includes the following steps:

### Data Definition Language (DDL) Extension
A software module will be developed to add new keywords to the **Structured Query Language (SQL)**. Instead of the traditional `CREATE TABLE` command, the system will introduce a new command: `CREATE IMMUTABLE_TABLE`.
*   **Academic Justification:** This allows defining the **Data Contract** at the design phase, clarifying the developer's intention that this table is dedicated to permanent, immutable records.

### Enforcement Mechanism at Engine Level
When the new command is invoked, the system internally performs the following:
*   Creates the table with strict **Constraints** preventing **UPDATE** and **DELETE** operations.
*   Modifies **Storage Parameters** to ensure that **Pages** allocated for this table are treated as **Read-Only** after initial writing.
*   Intercepts any attempt to directly access **data files (WAL files)** to modify records.

### Versioning & History
If data correction is required, the system does not allow direct modification. Instead, it mandates inserting a new record referencing the previous record (**Linked List Structure**), thereby preserving the complete **Audit Trail**.

## 4. Research Contributions & Extensions
To enhance the scientific and practical value of the thesis, the following ideas are proposed for integration within the study scope:

### A. Integration with Cryptographic Hashing Chain
*   **Idea:** Preventing modification programmatically is insufficient; it must be proven mathematically. It is proposed that the system automatically generates a **Hash** for each new record and links it to the hash of the previous record (similar to **Blockchain** but within the database).
*   **Benefit:** This allows immediate detection of any potential tampering in physical storage files, even if the database application layer is bypassed.

### B. Performance & Storage Overhead Analysis
*   **Idea:** Conduct a precise comparative study between traditional tables and immutable tables regarding **Write Throughput** and consumed storage size.
*   **Benefit:** Determine whether the **Integrity Cost** is acceptable in high-performance systems (e.g., **High-Frequency Trading Systems**).

### C. Compliance & GDPR Considerations
*   **Idea:** Discuss the issue of the **Right to be Forgotten** in the context of immutable tables.
*   **Proposed Solution:** Develop a **Cryptographic Shredding** mechanism, where data is effectively deleted by removing its specific encryption keys without needing to modify the record itself, achieving a balance between integrity and privacy.

### D. Decentralized Audit Model
*   **Idea:** Allow trusted external parties to verify record integrity (**Verification**) without granting them access to the data content (**Zero-Knowledge Proof**).
*   **Benefit:** Enhances transparency in governmental systems or supply chains.

## 5. Expected Conclusion
This study is expected to prove that integrating **Immutable Storage Techniques** within open-source Relational Database Systems provides an effective additional security layer against **Insider Threats**, while maintaining system efficiency. Furthermore, the thesis will present a **Prototype** for a PostgreSQL extension that can be adopted as a security standard in sensitive systems.
